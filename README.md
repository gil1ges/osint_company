# osintcli

Небольшой Go CLI для OSINT-анализа компании.

Что умеет:

- собирать базовый профиль компании
- собирать цифровой след по домену
- использовать SpiderFoot как основной источник для digital footprint, если он доступен
- генерировать отчеты в `json`, `html`, `md`, `txt`

Основные входные параметры:

- `--company`
- `--inn`
- `--domain`

Примеры запуска:

```bash
go run ./cmd/osintcli --company "ЗАЗЕКС" --domain zuzex.ru --module all --format html --output ./reports
go run ./cmd/osintcli --company "Яндекс" --domain ya.ru --module all --format json --output ./reports
```

Сборка:

```bash
go build ./...
```

Тесты:

```bash
go test ./...
```

Полезно знать:

- HTML-отчет лежит в `reports/`
- `SpiderFoot` подключается через `OSINTCLI_SPIDERFOOT_URL`
- если внешние источники недоступны, проект использует fallback passive sources

Пример env:

```dotenv
OSINTCLI_SPIDERFOOT_URL=http://127.0.0.1:5001
```
