# What

# AuthType = None

# AUTH Type = AWS_IAM
1. How to get it to work
   1. make sure to add InvokeFunctionURL to the caller's role
   2. make sure to point out that InvokeFunction in caller's role is not needed and wont work
   
   ```
      is not authorized to perform: lambda:InvokeFunction on resource: arn:aws:lambda:eu-west-1:865197160877:function:ravi_cross_account_invoke_test:$LATEST because no identity-based policy allows the lambda:InvokeFunction action
   ```
   
2. curl example
3. awscurl example


# Compare with API Gateway
API Gateway -> 29 secs
Lambda Function URL -> 15 minutes