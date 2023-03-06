![alt tag](https://upload.wikimedia.org/wikipedia/commons/2/23/Golang.png)

[![License](https://img.shields.io/github/license/peterxcli/basic-auth-gin)](https://github.com/peterxcli/basic-auth-gin/blob/master/LICENSE) 

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/peterxcli/basic-auth-gin)](https://github.com/peterxcli/basic-auth-gin/releases) 

[![Go Version](https://img.shields.io/github/go-mod/go-version/peterxcli/basic-auth-gin)](https://github.com/peterxcli/basic-auth-gin/blob/master/go.mod) 

[![DB Version](https://img.shields.io/badge/DB-MongoDB--latest-blue)](https://github.com/peterxcli/basic-auth-gin/blob/master/go.mod) 

Welcome to **basic-auth-gin** v1

The fastest way to deploy a restful api's with [Gin Framework](https://github.com/gin-gonic/gin/) with a structured project that defaults to **MongoDB** database and **JWT** authentication middleware

## Configured with

- [jwt-go](https://github.com/golang-jwt/jwt): JSON Web Tokens (JWT) as middleware
- Go Modules
- Built-in **Custom Validators**
- Built-in **CORS Middleware**
- Built-in **RequestID Middleware**
- google oauth api
- sendGrid email api
- SSL Support
- Enviroment support
- Unit test
- swagger docs
- And few other important utilties to kickstart any project

-------------------

## Prerequisite
### google oauth api
1. create oauth-client at https://console.cloud.google.com/apis/credentials
2. set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env` to your oauth-client id and secret
3. set `REDIRECT_URI` for the google oauth callback
### sendGrid email api
1. if you have your own mail system, you can change the `sendEmail` function at `controllers/user.go:146` and connect to your smtp server
2. if you dont have, try my free alternative: `cloudflare` + `sendgrid`
3. after you get the sengrid email api key, set `SENDGRID_API_KEY` in `.env` to that

## Installation

```
$ git clone https://github.com/peterxcli/basic-auth-gin.git
```

## Running Your Application

Rename `.env_rename_me` to `.env` and place your credentials

```
$ mv .env_rename_me .env
```

Generate SSL certificates (Optional)

> if you need ssl, change `SSL=FALSE` to `SSL=TRUE` in the `.env` file, then

```
$ make https
```

> Make sure to change the values in .env for your database

```
$ make install
$ make run
```

* every time you run `$ make run` it would regenerate the swagger docs base on your comments

> link to http://localhost:9000/swagger/index.html to view the openAPI docs

## Building Your Application

```
$ go build -v
```

```
$ ./<your_package_name>
```

## Testing Your Application

```
$ make test
```

---

## Acknowledge
thanks [Massad -> gin-boilerplate](https://github.com/Massad/gin-boilerplate) 
for enabling me to build the gin/mongoDB user auth template
