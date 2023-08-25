
# Authentication

## Auth with Insights
Authentication in Insights can be achieved using either `user` or `service accounts`.
Both retrieve and cache a token. This token can then be used is subsequent actions.

### User 

Users can log in using the following command: `kxi auth login`. This command will go through the oAuth flow 
and will redirect users to the Insights UI login page. Upon providing valid
authentication credentials, the login will be successful, and the user will be 
redirected to the success page. The `auth login` command will be completed at this point.
```
$ kxi auth login 
```
![redirect login](authlogin.png)


![auth successful](successlogin.png)

***Note***
    The default `auth-client` to authenticate a user with  is `insights-app`. This
    user can be updated by setting the value of `auth.client` in the `cli-config` file.

### Service account 
To log in using a service account, the `auth login` command provides an additional 
argument `--serviceaccount`. The `auth.serviceaccount.id` and `auth.serviceaccount.secret` 
values are read from the cli-config by default.

To specify the `client.id` and `client.secret` values directly as arguments, you can use the `--client.id` and `--client.secret` options. 

***Note***
    The `client.id` and `client.secret` are deprecated  and will be replaced with
    `auth.serviceaccount.id` and `auth.serviceaccount.secret` in future releases. Make sure 
    to update your authentication parameters accordingly.

```
$ kxi auth login --serviceaccount
```

Authenticating without a cli-config configured prompts for the id and secret 
```
$ kxi auth login --serviceaccount
Please enter a service account id to connect with: test-publisher
Please enter a service account secret to connect with (input hidden):
Re-enter to confirm (input hidden): 
```

Enviornment variables can be set if the serviceaccount_secret/id has not been configured:
```
$ export KXI_SERVICEACCOUNT_ID=test-publisher
$ export KXI_SERVICEACCOUNT_SECRET=<SECRET>
$ kxi auth login --serviceaccount
```
### Profiles 

Profiled logins are supported, allowing you to authenticate with multiple 
profiles simultaneously.  When using profiled logins, you can specify 
different profiles using the `--profile` flag during authentication.

In this case, the command will use a token specifically associated with the "prod" environment.
```
kxi --profile prod auth login
```
To authenticate with the profile named `uat`:
```
kxi --profile uat auth login
```

This how the credentials file looks with multiple profiles 
```
$ cat ~/.insights/credentials 
[default]
token = eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3eUJLcW8tbC05RmZqaHNYek5FOEhIVUpEUlFMQUVXMmpkMHdwdzJyRm5nIn0.eyJleHAi...
type = serviceaccount
[uat]
token = eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnU05ENFhGNUp5MVZVbnh6bW9nTWZsM2tkRGVDTEhGMWk2S1FJZ25vSTBVIn0.eyJleHAiOjE2ODk4......
type = user
[prod]
token = eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnU05ENFhGNUp5MVZVbnh6bW9nTWZsM2tkRGVDTEhGMWk2S1FJZ25vSTBVIn0.eyJleHAiOjE2ODk4NT....
type = user
```


## General

During the authentication process, the tokens generated are cached and 
saved by default to the location `~/.insights/credentials`. The location of this can be updated by 
adding the `auth.cache_file` var to the `cli-config` file.
These tokens are valid for a duration of 5 minutes.

When an action is called that requires a token, for example, when using the command 
`kxi assembly list`, the token is first validated to ensure it has not expired. 
This validation process can be found in the function [check_cached_token_active](../kxicli/resources/auth.py#check_cached_token_active). 

In the event that the token has expired, a new token is requested. 
The path taken to obtain a new token depends on the type of token needed, 
whether it's for a `service account` or a `user`. The determination of 
the token type and the subsequent process can be found in the function [determine_token_type](../kxicli/resources/auth.py#determine_token_type). 


In the following example, the assembly list retrieval process involves obtaining a new token if the current token has expired.
 The CLI function interacts with the internal `Assembly` class through the [assembly list API](../kxicli/commands/assembly.py#_list_assemblies).

When the `Assembly.list()` method is invoked, it triggers the execution of the [check_cached_token](../kxicli/resources/auth.py#CliAuthroizer/check_cached_token) API. This API reads the current token from disk, if one exists, and verifies its validity.
If the token has expired, a new token is requested seamlessly without requiring any user interaction.

This mechanism ensures a smooth token renewal process, allowing the assembly list 
retrieval to continue functioning even when the original token has expired.


```
$ kxi assembly list
# Browser window is opened
ASSEMBLY NAME  RUNNING  READY
dfx-assembly   False    False
iot-assembly   False    False

$ kxi assembly list
ASSEMBLY NAME  RUNNING  READY
dfx-assembly   False    False
iot-assembly   False    False

```

## How we use tokens

The tokens are used internally within the following areas:
* [Client](../kxicli/commands/client.py)
* [Assembly](../kxicli/commands/assembly.py) 
* [Query](../kxicli/commands/query.py)
* [Entitlements](../kxicli/commands/entitlement.py)


## Client id/secret legacy code 

The [get_access_token](../kxicli/commands/auth.py#get_access_token) function located in auth.py, 
receives the decorators `client_id` and `client_secret` as arguments, but they are not directly 
used within the function's body. The reason for this is that these values are required within the 
click context for determining the serviceaccount_id using [get_serviceaccount_id](../kxicli/options.py#get_serviceaccount_id) 
and the serviceaccount_secret using [get_serviceaccount_id](../kxicli/options.py#get_serviceaccount_secret).

Similarly, the [login](../kxicli/commands/auth.py#login) function, also located in `auth.py`, 
takes the decorators `client_id` and `client_secret` as arguments without using them directly within the function. 
