use hmac::Hmac;
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yewtil::future::LinkFuture;
use pwned::api::*;

pub struct Model {
    link: ComponentLink<Self>,
    email: String,
    password: String,
    password2: String,
    processing: bool
}

pub enum Msg {
    UpdateEmail(String),
    UpdatePassword(String),
    UpdatePassword2(String),
    SignUp,
    Done(String)
}

impl Model {
    async fn send_signup(password: &str) -> Result<String, JsValue> {


        /*
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init("http://ip.jsontest.com/", &opts)?;
        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().unwrap();
        let text = JsFuture::from(resp.text()?).await?;
        Ok(text.as_string().unwrap())
        */

        let pwned = PwnedBuilder::default()
        .build().unwrap();

        match pwned.check_password(password).await {
            Ok(pwd) => Ok(format!("Pwned? {} - Occurrences {}", pwd.found, pwd.count)),
            Err(e) => Err(format!("Error: {}", e).into()),
        }
        


    }
}


impl Component for Model {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            email: "".to_string(),
            password: "".to_string(),
            password2: "".to_string(),
            processing: false,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::UpdateEmail(t) => self.email = t,
            Msg::UpdatePassword(t) => self.password = t,
            Msg::UpdatePassword2(t) => self.password2 = t,
            Msg::SignUp => {
                self.processing = true;

                let mut res=[0u8; 8];
                pbkdf2::pbkdf2::<Hmac<Sha256>>(self.password.as_bytes(), b"", 1, &mut res);

                self.password2 = format!{"{:X?}", res};

                client_core::send_signup();
                
                let password = self.password.clone();

                self.link.send_future(async move {
                    match Self::send_signup(&password).await {
                        Ok(text) => {
                            Msg::Done(text)
                        },
                        Err(_) => {
                            unimplemented!()
                        }
                    }
                });
            },
            Msg::Done(text) => {
                self.processing = false;
                self.password = text;
            }
        }
        true
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        html!{
            <fieldset disabled=self.processing >
                <label for="email">{"email:"}</label>
                <input type="email" id="email" oninput=self.link.callback(|e: InputData| Msg::UpdateEmail(e.value))/>
                <br/>
                {
                    if validator::validate_email(&self.email) {
                        "good"
                    } else {
                        "bad"
                    }
                }
                <br/>
                <label for="password">{"password:"}</label>
                <input type="password" id="password" oninput=self.link.callback(|e: InputData| Msg::UpdatePassword(e.value))/>
                <label for="password2">{"password gain:"}</label>
                <input type="password" id="password2" oninput=self.link.callback(|e: InputData| Msg::UpdatePassword2(e.value))/>
                <br/>
                {
                    if self.password != self.password2 {
                        "not same"
                    } else {
                        "same"
                    }
                }
                <br/>
                {
                    {
                        let user_inputs: Vec<_> = self.email.split(|c| c == '@' || c == '.').collect();
                        match zxcvbn::zxcvbn(&self.password, &user_inputs) {
                            Ok(e) => e.score(),
                            Err(_) => 0,
                        }
                    }
                }
                

                <br/>
                <button onclick=self.link.callback(|_| Msg::SignUp)>{"Sign Up"}</button>
                <br/>
                <>{format!{"email: {} - password: {} - password2: {}", self.email, self.password, self.password2}}</>
            </fieldset>
        }
    }
}
