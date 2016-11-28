**Note:** This only works under **fabric branch v0.6**

## fabric-sdk-golang
This sdk provide ability similar to rest api, enroll、regisar、get certs and deploy、 invoke、 query、get transactions. In golang/api/api.yaml, you can config security and privacy. Note, in api.yaml only have one server address, this sdk should with the use of [fabric-gateway-filter](https://github.com/ai74p091/fabric-gateway-filter), fabric-gateway-filter will hide all fabric cluster and can filter which request is allowed, so it is more secure and easy to sdk.

## how to use
This sdk depends on fabric and fabric's vendor, you should clone this sdk to **github.com/hyperledger/fabric/sdk**, this is a good way to reslove depends.A demo is in golang/api/api_test.go, it shows how call api functions.
