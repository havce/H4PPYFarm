# H4PPY Farm

## Dependencies

- PyYAML
- Flask

To install them:

```bash
$ pip install PyYAML Flask
```

## Usage

Create file a called `farm.yml` in `server/` and write there your configuration.  
The possible configuration options are:

| **option**    | **provided by** | **default value** | **description |
|---------------|-----------------|-------------------|---------------|
| port          | env, farm.yml   | 8080              | the server port |
| tick_duration | env, farm.yml   | 60                | the duration of a game tick, in seconds |
| flag_lifetime | env, farm.yml   | 5                 | the time for which a flag is valid, expressed in game ticks |
| submit_period | env, farm.yml   | 2                 | the period with which the server will try to send new flags to the game system |
| batch_limit   | env, farm.yml   | 100               | the maximum number of flags to send to the game system in one request |
| flag_format   | env, farm.yml   | [A-Z0-9]{31}=     | a regex expression that matches every flag |
| database      | env, farm.yml   | :memory:          | a sqlite3 database path |
| team_token    | env, farm.yml   | -                 | the team token to use when posting flags to the game system |
| system_url    | env, farm.yml   | -                 | the URL to which the server should try and send the flags to |
| teams         | env, farm.yml   | -                 | the addresses of every team in the game, expressed as a range |
| password      | env, farm.yml   | -                 | the password needed to access the server |
| secret_key    | env             | -                 | the secret key used by Flask to encrypt sessions |

> [!NOTE]
> When passing a configuration option as an environment variable the name of said variable is `FARM_{config_name.upper()}`  

> [!NOTE]
> Ranges can be specified using `{a..b}`
