# AWS Lambda Function URLs

On 06 April 2022, AWS announced AWS Lambda Function URLs, a new feature thats lets you add **HTTPS Endpoints** to your existing lambda functions and optionally configure Cross-Origin Resource Sharing (CORS) headers.

A function URL is a dedicated HTTPS endpoint for your Lambda function. You can create and configure a function URL through the Lambda console or the Lambda API. When you create a function URL, Lambda automatically generates a unique URL endpoint for you. Once you create a function URL, its URL endpoint never changes. Function URL endpoints have the following format:
```text
https://<url-id>.lambda-url.<region>.on.aws
```
Function URLs are dual stack-enabled, supporting IPv4 and IPv6. After you configure a function URL for your function, you can invoke your function through its HTTP(S) endpoint via a web browser, curl, Postman, or any HTTP client.

## Security and auth model for Lambda function URLs

You can control access to your Lambda function URLs using the AuthType parameter combined with resource-based policies attached to your specific function. The configuration of these two components determines who can invoke or perform other administrative actions on your function URL.

The AuthType parameter determines how Lambda authenticates or authorizes requests to your function URL. When you configure your function URL, you must specify one of the following AuthType options:

* **AWS_IAM –** Lambda uses AWS Identity and Access Management (IAM) to authenticate and authorize requests based on the IAM principal's identity policy and the function's resource-based policy. Choose this option if you want only authenticated IAM users and roles to invoke your function via the function URL.

* **NONE** – Lambda doesn't perform any authentication before invoking your function. However, your function's resource-based policy is always in effect and must grant public access before your function URL can receive requests. Choose this option to allow public, unauthenticated access to your function URL.

### AuthType = None

When your function URL auth type is NONE and you have a resource-based policy that grants public access, any unauthenticated user with your function URL can invoke your function.


### AUTH Type = AWS_IAM

This is a little tricky to understand, but basically we need to follow two principles.

If the principal making the request is in the **same AWS account as the function URL**, then the principal must **either** have lambda:InvokeFunctionUrl permissions in their identity-based policy, or have permissions granted to them in the function's resource-based policy.  
However,  
If the principal making the request is in **a different account**, then the principal must have **both** an identity-based policy that gives them lambda:InvokeFunctionUrl permissions and permissions granted to them in a resource-based policy on the function that they are trying to invoke. 

But, here is the kicker. If your function URL uses the AWS_IAM auth type, **we must sign each HTTP request using AWS Signature Version 4 (SigV4)**.  
Tools such as awscurl, Postman, and AWS SigV4 Proxy offer built-in ways to sign your requests with SigV4.

What this means is, we need to pass the  aws_access_key_id, aws_secret_access_key and aws_session_token with each request, and also sign the requests.  

Here is How Signature Version 4 works
1. Create a canonical request.
2. Use the canonical request and additional metadata to create a string for signing.
3. Derive a signing key from your AWS secret access key. Then use the signing key, and the string from the previous step, to create a signature.
4. Add the resulting signature to the HTTP request in a header or as a query string parameter.

When an AWS service receives the request, it performs the same steps that you did to calculate the signature you sent in your request. AWS then compares its calculated signature to the one you sent with the request. If the signatures match, the request is processed. If the signatures don't match, the request is denied.

With curl, we can invoke the requests like 
```text

curl --location --request GET $url \
    --header 'Content-Type: application/json' \
    --header "x-amz-security-token:$AWS_SESSION_TOKEN"\
    --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" --aws-sigv4 aws:amz:eu-west-1:lambda
  
```

Using awscurl, the credentials can be read from environment variables
```text

awscurl -XPOST --service lambda $url

```

However, if we are using python in our lambda for example, we need to complete Signature Version 4 signing process
The good news is, we can simply get the credentials via a call to boto session

```text
    session = Session()
    creds = session.get_credentials()
    print(f"{creds.access_key}, {creds.secret_key}, {creds.token}")
```

The bad news being, we need to implement the 4 steps above, before we can invoke the request.

A sample code is attached, which invokes the lambda url using aws-sigv4

But I must re-emphasise, this is required **only when the function URL uses the AWS_IAM auth type**

## API Gateway vs Lambda Function URLs
So should we replace all API gateway calls with Lambda function URLs :)
The long answer is as below:

The most important thing to note here that **lambda max execution timeout is 15 minutes, while for API gateway it's 29 sec**.  
Also, if we are using a Combination of API Gateway + lambda, we pay the cost of both. 

However, with API Gateways, we also get **Caching**, **REST**, **WebSockets**, **Request/Response Validation and mapping** along with advanced authorizations using **Cognito, API keys, Lambda authorizers**

**Requests Throttling** is an interesting comparison, because API gateway supports it inherently, 
while in Lambda function urls, we can only do a basic request throttling using Lambda reserve concurrency.

Here is the use case matrix

| Lambda function URLs | API Gateway |
| --- |---|
| Single function, simple microservice | SaaS applications with Authentication, Caching, Usage Plans |
| Form validators, webhook handlers | Real-time applications using Websockets |
| Long-running or Long-polling cases | Cases where API response time is less than 29 seconds |

One missing feature in Lambda Function URL as of today is that there are no access logs in Cloudwatch like API gateway