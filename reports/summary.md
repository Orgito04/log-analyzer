# Log Analysis Summary

## Top suspicious IPs

| ip          |   requests |   failed_requests |   unique_paths |   score |
|:------------|-----------:|------------------:|---------------:|--------:|
| 192.0.2.1   |          2 |                 2 |              1 |     6.7 |
| 127.0.0.1   |          1 |                 0 |              1 |     0.6 |
| 203.0.113.5 |          1 |                 0 |              1 |     0.6 |

## High request rate alerts

None detected.


## Failed requests sample

| ip        | time                      | method   | path          |   status |   size | referer   | agent       |
|:----------|:--------------------------|:---------|:--------------|---------:|-------:|:----------|:------------|
| 192.0.2.1 | 2025-12-11 21:55:03+00:00 | POST     | /wp-login.php |      401 |    345 | -         | Mozilla/5.0 |
| 192.0.2.1 | 2025-12-11 21:55:04+00:00 | POST     | /wp-login.php |      401 |    345 | -         | Mozilla/5.0 |