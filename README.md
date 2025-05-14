# H4PPY Farm

## Dependencies

- PyYAML
- Flask
- Flask-SQLAlchemy
- requests
- waitress

To install them:

```bash
$ pip install PyYAML Flask requests waitress
```

## Usage

Create file a called `farm.yml` in `server/` and write there your configuration.  
The possible configuration options are:

| **option**     | **provided by** | **default value** | **description                                                                                      |
|----------------|-----------------|-------------------|----------------------------------------------------------------------------------------------------|
| port           | env, farm.yml   | 6969              | the server port                                                                                    |
| tick_duration  | env, farm.yml   | 120               | the duration of a game tick, in seconds                                                            |
| flag_lifetime  | env, farm.yml   | 5                 | the time for which a flag is valid, expressed in game ticks                                        |
| submit_period  | env, farm.yml   | 10                | the period (in seconds) with which the server will try to send new flags to the game system        |
| submit_timeout | env, farm.yml   | 10                | the time in seconds after which a request to the game system should timeout                        |
| batch_limit    | env, farm.yml   | 1000              | the maximum number of flags to send to the game system in one request                              |
| flag_format    | env, farm.yml   | [A-Z0-9]{31}=     | a regex expression that matches every flag                                                         |
| database       | env, farm.yml   | :memory:          | a sqlite3 database path                                                                            |
| secret_key     | env             | random            | the secret key used by Flask to encrypt sessions                                                   |
| team_token     | env, farm.yml   | -                 | the team token to use when posting flags to the game system (only used for the HTTP protocol)      |
| system_url     | env, farm.yml   | -                 | the URL to which the server should try and send the flags to (it must specify a protocol with ://) |
| system_type    | env, farm.yml   | forcad            | the type of the game system (for now only `ForcAD` type is implemented)                            |
| teams          | env, farm.yml   | -                 | the addresses of every team in the game, expressed as a range                                      |
| password       | env, farm.yml   | -                 | the password needed to access the server                                                           |
| hfi_source     | env, farm.yml   | ./hfi             | the path to the source root of the hfi executable                                                  |
| hfi_cache      | env, farm.yml   | ./hfi-cache       | the path to the directory to be used to store the hfi binaries                                     |

> [!NOTE]
> When passing a configuration option as:
> - an environment variable, the name of said variable is `FARM_{config_name.upper()}`  
> - a YAML entry, the name of said entry is `config_name.replace("_", "-")`

> [!NOTE]
> Ranges can be specified using `{a..b}` inclusive
