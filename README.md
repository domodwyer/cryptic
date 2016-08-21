[![Build Status](https://travis-ci.org/domodwyer/cryptic.svg?branch=master)](https://travis-ci.org/domodwyer/cryptic) [![GoDoc](https://godoc.org/github.com/domodwyer/cryptic?status.svg)](https://godoc.org/github.com/domodwyer/cryptic)

<p align="center">
<img src="https://s3-eu-west-1.amazonaws.com/iab-assets/cryptic-header.png" />
</p>
<p align="center">
<em>Manage API keys, passwords, certificates, etc. with infrastructure you already use.</em>
</p>
<br /><br />

- Proven encryption, by default uses *AES-256* with *SHA-512* for integrity checks.
- Supports multiple data stores - use infrastructure you already have.
- No dependency hell: single binary to store a secret, one more to fetch.
- Use [Amazon KMS](https://aws.amazon.com/kms/) key wrapping to further control access to sensitive information.
- Super **simple** to use!

# Usage
Put a password somewhere: 
```
./put -name=ApiKey -value="be65d27ae088a0e03fd8e1331d90b01649464cb7"
```

Get a password back out somewhere else:
```
./get -name=ApiKey
```

Or as part of a script (say, an environment variable):
```
export API_KEY=$(get -name=ApiKey)
```

# Installation
Download a [release](https://github.com/domodwyer/cryptic/releases) for the binaries and get going straight away.

Drop a simple YAML file in the same directory as the binary (`./cryptic.yml` or `/etc/cryptic/cryptic.yml`  for a global configuration) to configure encryption and stores - below is a minimal example:

```yml
Store: "db"
Encryptor: "aes"

DB:
  Host: "127.0.0.1:3306"
  Name: "db-name"
  Username: "root"
  Password: "password"

AES:
  Key: "anAesTestKey1234" # 16, 24, or 32 characters long. More is better.
  HmacKey: "superSecretHmacKey-867a13rr3117aac4£*"
```

# Configuration
Bellow are all the configurable options for Cryptic:
```yml
# Store can be either 'redis' or 'db'
Store: "db"

DB:
  Host: "127.0.0.1:3306"
  Name: "db-name"
  Username: "root"
  Password: "password"
  Table: "secrets"
  KeyColumn: "name"
  ValueColumn: "data"

Redis:
  Host: "127.0.0.1:6379"
  DbIndex: 0
  Password: ""
  ReadTimeout: "3s"
  WriteTimeout: "5s"
  MaxRetries: 0

# Encryptor can be either 'aes' or 'kms'
Encryptor: "kms"

# AES key size is variable (16, 24, 32 chars) - uses SHA512 for HMAC
AES:
  Key: "changeme"
  HmacKey: "changeme"

# KMS uses AES-256 and SHA512 for HMAC
KMS:
  KeyID: "427a117a-ac47-4c90-b7fe-b33fe1a7a241"
  Region: "eu-west-1"
```

# Database

The database table is a simple key-value table, but **must** include a UNIQUE constraint on the key column. Below is a SQL snippet suitable for the default settings:

```sql
CREATE TABLE `secrets` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL DEFAULT '',
  `data` blob NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
```

# Amazon KMS / Key Wrapping
[Amazon KMS](https://aws.amazon.com/kms/) is a key-management service that provides key wrapping and auditing features (and more) that you can take advantage of to further secure your secrets.

Using IAM roles you can control read access to only your production machines for example, or only your dev team, or perhaps only certain users.

Cryptic gets a secure 512-bit key from KMS and uses that to encrypt your data. To decrypt, first the stored key is sent to KMS for decryption, and the result is used to decrypt the AES-256 encrypted secret locally - your encrypted secret can't be recovered without both KMS and your AES secret.

Included is a [terraform](https://www.terraform.io/) configration to generate a KMS key - `terraform apply` and it'll return a key ID such as `427a117a-ac47-4c90-b7fe-b33fe1a7a241` (or make it [manually](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html)).

Assuming you have the AWS CLI installed and credentials configured, all you need is to configure like above and go!

# Library Usage / Source
```
go get -v github.com/domodwyer/cryptic
```

For an example of how to use the library, check out the `put` and `get` binaries - each are only 50 lines long!

The library supports storage of binary secrets, though the CLI tools currently don't. Retries/backoff/circuit-breaking/etc is left to the library user.

PR's welcome - please target to the `dev` branch.

Oh, and **vendor this** and everything else if you value your sanity.

# Testing
Unit tests cover every aspect of the library, including integration tests.

Don't run integration tests against production systems, they might go wild and ruin your day.

For redis: `REDIS_HOST="localhost:6379" go test ./... -v -tags="integration"`

For KMS: `AWS_REGION="eu-west-1" KMS_KEY_ID="<your key>" go test ./... -v -tags="awsintegration"`

Or combine them for double the fun.

# Credits

The idea was largely taken from [credstash](https://github.com/fugue/credstash) - I just didn't want to install python + dependencies, and I wanted to use redis. Many of the same security implications mentioned on the credstash README apply to Cryptic too.

# Improvements

- More backends (S3/DynamoDB/memcached/etc)
- More encryptors
- Secret versioning/rotation/expiration
- Support for pipelined requests to backends to reduce latency
- Redis transactional existing-key check with `WATCH`
