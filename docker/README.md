# Rizin Test Docker Container

Docker-образ для полного тестирования rizin и rz-tracetest (проверка IR/RzIL).

## Сборка

```bash
# Из корня репозитория rizin
docker build -f docker/Dockerfile.test -t rizin-test .
```

## Запуск тестов

```bash
docker run --rm rizin-test
```

Выполняются:
- **Unit tests** — il_definitions, il_vm, il_validate, il_helpers, il_reg, analysis_op и др.
- **Integration tests** — analysis_il и др.
- **DB tests** — rz-test (asm, disasm, analysis, esil, rzil для всех архитектур)
- **rz-tracetest** — проверка работоспособности

## Интерактивный режим

```bash
docker run -it --rm rizin-test /bin/bash
# Внутри контейнера:
cd /rizin
meson test -C build --suite unit
meson test -C build --suite db
rz-tracetest --help
```

## Проверка IR через rz-tracetest

Для проверки IR нужен файл трейса (.frames). Пример:

```bash
docker run -it --rm -v /path/to/traces:/traces rizin-test \
  rz-tracetest /traces/mytrace.frames
```

Трейсы генерируются патченными эмуляторами (VICE для 6502, SameBoy для gb, QEMU для Hexagon).
