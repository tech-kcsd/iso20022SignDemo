# iso20022SignDemo

DEMO подписания ISO20022 документа

# Требования

- Java 17+
- Maven 3.8+

# User Guide

1. В `Main.java` в `XML_SAMPLE` прописать XML для подписи
2. Запустить программу с аргументами: --cert <путь до файла с ключем GOST .p12> --password <пароль от ключа>
3. В STDOUT будет выведена XML с ISO20022 подписью
