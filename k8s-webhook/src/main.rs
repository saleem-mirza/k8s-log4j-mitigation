use actix_web::{http::header::ContentType, web, App, HttpResponse, HttpServer};
use base64::encode;
use clap::Arg;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde_json::{json, Value};
use std::process::exit;

async fn webhook(data: web::Bytes) -> HttpResponse {
    let request = match serde_json::from_slice::<Value>(&data) {
        Ok(x) => x,
        _ => Value::Null,
    };

    let mut response = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": request["request"]["uid"],
            "allowed": true,
            "patch": "",
            "patchType": "JSONPatch",
            "status": {
                "code": 200,
                "message": ""
            },
            "warnings":[]
        }
    });

    if request == Value::Null {
        response["response"]["allowed"] = json!(false);
        response["response"]["status"]["code"] = json!(403);
        response["response"]["status"]["message"] = json!("Invalid JSON payload");
        return HttpResponse::Ok().set(ContentType::json()).body(response);
    }

    if request["apiVersion"] != "admission.k8s.io/v1"
        && request["apiVersion"] != "admission.k8s.io/v1beta1"
    {
        response["response"]["allowed"] = json!(false);
        response["response"]["status"]["code"] = json!(403);
        response["response"]["status"]["message"] = json!("Wrong API version");

        return HttpResponse::Ok().set(ContentType::json()).body(response);
    }

    if request["request"]["kind"]["group"] == ""
        && request["request"]["kind"]["version"] == json!("v1")
        && request["request"]["kind"]["kind"] == json!("Pod")
        && (request["request"]["operation"] == json!("CREATE")
            || request["request"]["operation"] == json!("UPDATE"))
    {
        let mut containers = vec![];
        let request_containers = request["request"]["object"]["spec"]["containers"]
            .as_array()
            .unwrap();

        for (i, _) in request_containers.iter().enumerate() {
            match request_containers[i].get("env") {
                None => {
                    containers.push(json!({
                        "op": "add",
                        "path": format!("/spec/containers/{}/env", i),
                        "value": [{ "name": "LOG4J_FORMAT_MSG_NO_LOOKUPS", "value": "true" }]
                    }));
                }
                Some(env) => {
                    let mut found = false;
                    let env_array = env.as_array().unwrap();

                    for (j, _) in env_array.iter().enumerate() {
                        if env_array[j]["name"] == json!("LOG4J_FORMAT_MSG_NO_LOOKUPS") {
                            containers.push(json!({
                                "op": "replace",
                                "path": format!("/spec/containers/{}/env/{}/value", i, j),
                                "value": "true"
                            }));
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        containers.push(json!({
                            "op": "add",
                            "path": format!("/spec/containers/{}/env/0", i),
                            "value": { "name": "LOG4J_FORMAT_MSG_NO_LOOKUPS", "value": "true" }
                        }));
                    }
                }
            };
        }

        response["response"]["allowed"] = json!(true);
        response["response"]["patch"] = json!(encode(serde_json::to_string(&containers).unwrap()));
    }

    HttpResponse::Ok()
        .set(ContentType::json())
        .body(serde_json::to_vec(&response).unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let matches = clap::App::new("log4j-mutating-webhook")
        .version("1.0.0")
        .author("Muhammad Saleem Mirza")
        .arg(
            Arg::new("cert")
                .long("cert")
                .takes_value(true)
                .default_value("tls.crt")
                .help("set tls certificate path"),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .takes_value(true)
                .default_value("tls.key")
                .help("set tls key path"),
        )
        .get_matches();

    println!("Initializing certificates...");

    let mut ctx = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    if ctx
        .set_private_key_file(matches.value_of("key").unwrap(), SslFiletype::PEM)
        .is_err()
    {
        eprintln!("\nInvalid tls certificate key... terminating");
        exit(0);
    }

    if ctx
        .set_certificate_chain_file(matches.value_of("cert").unwrap())
        .is_err()
    {
        eprintln!("\nInvalid tls certificate... terminating");
        exit(0);
    }

    println!("Initialization: Done");

    HttpServer::new(|| App::new().route("/webhook", web::to(webhook)))
        .bind_openssl("0.0.0.0:443", ctx)?
        .run()
        .await
}
