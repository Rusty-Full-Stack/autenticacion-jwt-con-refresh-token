use actix_web::{dev::ServiceRequest, error, get, post, web, App, Error, HttpResponse, HttpServer};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use actix_web_httpauth::extractors::bearer::Config as BearerConfig;
use actix_web_httpauth::{extractors::bearer::BearerAuth, middleware::HttpAuthentication};

const LLAVE: &str = "12345";

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    iss: String,
    sub: String,
    exp: usize,
    iat: usize,
    tipo: String,
    user_id: usize,
}

#[derive(Serialize, Deserialize)]
struct LoginForm {
    usuario: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct LoginResult {
    token: String,
    refresh: String,
}

#[derive(Serialize, Deserialize)]
struct RefreshResult {
    token: String,
}

fn generar_token(
    iss: String,
    sub: String,
    duracion_en_minutos: i64,
    user_id: usize,
    tipo: String,
) -> String {
    let header = Header::new(Algorithm::HS512);
    let encoding_key = EncodingKey::from_secret(LLAVE.as_ref());

    let exp = (Utc::now() + Duration::minutes(duracion_en_minutos)).timestamp() as usize;
    let iat = Utc::now().timestamp() as usize;

    let my_claims = Claims {
        iss,
        sub,
        exp,
        iat,
        tipo,
        user_id,
    };

    encode(&header, &my_claims, &encoding_key).unwrap()
}

fn validar_token(token: String) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validacion = Validation::new(Algorithm::HS512);
    let decoding_key = DecodingKey::from_secret(LLAVE.as_ref());

    let resultado = decode::<Claims>(&token, &decoding_key, &validacion);

    match resultado {
        Ok(c) => {
            println!("Token es valido");
            Ok(c.claims)
        }
        Err(e) => {
            println!("Token es invalido");
            Err(e)
        }
    }
}

async fn validador(
    req: ServiceRequest,
    credenciales: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let Some(credenciales) = credenciales else {
        return Err((error::ErrorBadRequest("no se especifico el token"), req));
    };

    let token = credenciales.token();

    let resultado = validar_token(token.to_owned());

    match resultado {
        Ok(claims) => {
            println!("Los claims son: {:?}", claims);

            if claims.tipo != "refresh" {
                return Ok(req);
            } else {
                return Err((error::ErrorForbidden("no tiene acceso"), req));
            }
        }
        Err(e) => {
            println!("el token no es valido: {:?}", e);
            return Err((error::ErrorForbidden("no tiene acceso"), req));
        }
    }
}

#[post("/login")]
async fn login(form: web::Form<LoginForm>) -> HttpResponse {
    if form.usuario == "rusty" && form.password == "fullstack" {
        let iss = "Rusty Full Stack".to_owned();
        let sub = "Prueba".to_owned();
        let duracion_en_minutos: i64 = 5;
        let duracion_dia: i64 = 1440;
        let user_id = 1;

        let token = generar_token(
            iss.clone(),
            sub.clone(),
            duracion_en_minutos,
            user_id,
            "token-normal".to_owned(),
        );
        let refresh = generar_token(
            iss.clone(),
            sub.clone(),
            duracion_dia,
            user_id,
            "refresh".to_owned(),
        );

        let respuesta = LoginResult { token, refresh };

        HttpResponse::Ok().json(respuesta)
    } else {
        HttpResponse::Unauthorized().body("Login invalido")
    }
}

#[post("/refresh-token")]
async fn refresh_token(refresh_jwt: Option<BearerAuth>) -> HttpResponse {
    let Some(refresh_jwt) = refresh_jwt else {
        return HttpResponse::Forbidden().body("Token no enviado");
    };

    let claims = validar_token(refresh_jwt.token().to_owned());

    match claims {
        Ok(c) => {
            // crear el nuevo token normal
            if c.tipo == "refresh" {
                let iss = c.iss.to_owned();
                let sub = c.sub.to_owned();
                let duracion_en_minutos: i64 = 5;
                let user_id = c.user_id;
                let tipo = "token-normal".to_owned();

                println!("User Id en el refresh: {}", user_id);

                let token = generar_token(iss, sub, duracion_en_minutos, user_id, tipo);

                let resultado: RefreshResult = RefreshResult { token };

                HttpResponse::Ok().json(resultado)
            } else {
                HttpResponse::Unauthorized().body("")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body(""),
    }
}

#[get("/privado")]
async fn privado() -> HttpResponse {
    HttpResponse::Ok().body("privado")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validador);

        App::new()
            .app_data(BearerConfig::default().realm("jwt"))
            .service(login)
            .service(refresh_token)
            .service(web::scope("/admin").wrap(auth).service(privado))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
