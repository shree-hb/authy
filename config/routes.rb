Authy::Engine.routes.draw do
  
  post 'login' => 'login#create'
  delete 'login' => 'login#destroy'


  get 'login/hello' => 'login#hello'

end
