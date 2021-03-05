# Login Registration Backend 

Complete login registration backend system using Spring Boot.

- [x] Sring Boot
- [x] Sring Security
- [x] Java Mail
- [x] Email verification with expiry
- [x] Sring Boot

## Diagram
![Screenshot 2021-01-13 at 23 38 08](https://user-images.githubusercontent.com/40702606/104789980-15581a00-578e-11eb-998d-30f2e6a9f461.png)

### CURL
```
curl --location --request POST 'localhost:8080/api/v1/registration' \
--header 'Content-Type: application/json' \
--data-raw '{
    "firstName": "Moh",
    "lastName": "Rifkan",
    "email": "mohrifkan@goggxi.com",
    "password": "password123"
}'
```
