const api = {
  "openapi" : "3.0.0",
  "info" : {
    "title" : "SIWE Authentication Server",
    "version" : "0.1.0"
  },
  "servers" : [ {
    "description" : "Local environment",
    "url" : "http://localhost:8081"
  } ],
  "tags" : [ {
    "description" : "Endpoints for authenticating users.",
    "name" : "Authentication"
  } ],
  "paths" : {
    "/nonce" : {
      "get" : {
        "responses" : {
          "200" : {
            "content" : {
              "application/json" : {
                "schema" : {
                  "type" : "string"
                }
              }
            },
            "description" : "Nonce has been created."
          },
          "500" : {
            "description" : "Error creating a nonce."
          }
        },
        "summary" : "Get a nonce for a sign in request.",
        "tags" : [ "Authentication" ]
      }
    },
    "/sign_in" : {
      "post" : {
        "requestBody" : {
          "content" : {
            "application/json" : {
              "schema" : {
                "$ref" : "#/components/schemas/SigninData"
              }
            }
          },
          "description" : "The Sign in With Ethereum message and signature.",
          "required" : true
        },
        "responses" : {
          "200" : {
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/JWTPair"
                }
              }
            },
            "description" : "Successfully signed in."
          },
          "400" : {
            "description" : "Bad Request - nonce is invalid or does not match nonce in signature."
          },
          "500" : {
            "description" : "Error creating a nonce."
          }
        },
        "summary" : "Signs the user in, creating and returning a JWT.",
        "tags" : [ "Authentication" ]
      }
    },
    "/refresh" : {
      "post" : {
        "requestBody" : {
          "content" : {
            "application/json" : {
              "schema" : {
                "type" : "string"
              }
            }
          },
          "description" : "The user's current refresh token.",
          "required" : true
        },
        "responses" : {
          "200" : {
            "content" : {
              "application/json" : {
                "schema" : {
                  "$ref" : "#/components/schemas/JWTPair"
                }
              }
            },
            "description" : "Successfully refreshed tokens."
          },
          "400" : {
            "description" : "Bad Request - refresh token provided is not valid."
          },
          "500" : {
            "description" : "Error refreshing tokens."
          }
        },
        "summary" : "Checks a provided refresh token, returns a new access token and refresh token.",
        "tags" : [ "Authentication" ]
      }
    }
  },
  "components" : {
    "schemas" : {
      "JWTPair" : {
        "description" : "A JSON object containing two string fields, access_token and refresh_token.",
        "type" : "string"
      },
      "SigninData" : {
        "description" : "A JSON object containing two string fields, a Sign in With Ethereum message and signature. The nonce found in the decoded signature should match the nonce in the message."
      }
    },
    "securitySchemes" : {
      "JWTAuthorization" : {
        "bearerFormat" : "JWT",
        "description" : "JWT Bearer Token",
        "name" : "Authorization",
        "scheme" : "bearer",
        "type" : "http"
      }
    }
  }
};

window.onload = function() {
  //<editor-fold desc="Changeable Configuration Block">

  // the following lines will be replaced by docker/configurator, when it runs in a docker-container

  window.ui = SwaggerUIBundle({
      spec: api,
      dom_id: '#swagger-ui',
    });

  //</editor-fold>
};
