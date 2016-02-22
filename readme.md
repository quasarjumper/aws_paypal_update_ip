# Auto update PayPal IP in AWS SG

A script that will update the changing PayPal's API IP addresses on the AWS
Security Group.

## Installation

Ensure you have the boto library installed.

```
pip install boto
```


## Usage

You could just invoke this script in as a cron job every 30 min.
```
*/30 * * * * python2 /path/to/script/update_paypal_ip.py
```

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D


## Credits

Anish D
