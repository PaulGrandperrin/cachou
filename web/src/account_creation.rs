use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yewtil::future::LinkFuture;

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


impl Component for Model {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            email: String::default(),
            password: String::default(),
            password2: String::default(),
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

                client_core::send_signup(&self.password);
                
                let password = self.password.clone();

                self.link.send_future(async move {
                    match client_core::send_signup_req(&password).await {
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
                    if client_core::check_email(&self.email) {
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
                        client_core::check_pass(&self.password, &self.email)
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
