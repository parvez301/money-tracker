Money Tracker Backend

### Set Environment Variables

Update *project/server/config.py*, and then run:

```sh
$ export APP_SETTINGS="project.server.config.DevelopmentConfig"
```

or

```sh
$ export APP_SETTINGS="project.server.config.ProductionConfig"
```

Set a SECRET_KEY:

```sh
$ export SECRET_KEY="change_me"
```


```

Create the tables and run the migrations:

```sh
$ python manage.py create_db
$ python manage.py db init
$ python manage.py db migrate
```

### Run the Application

```sh
$ python manage.py runserver
```


### Testing



```sh
$ python manage.py test
```

### API EndPoints

> ``` 
> /auth/login  login endpoint
>```
> ``` 
> /auth/register register endpoint
> ```
> ```
> /auth/status      check user status
> ```
> ```
> /auth/user/expenses Expense list
> ```
> ``` 
> /auth/user/categories categories List
> ```
> ```
> /auth/user/add-expense Add New Expense
> ```
> ```
> /auth/user/add-category Add New Category
> ``` 
> ```
> /auth/user/dashboard 
> ``` 
