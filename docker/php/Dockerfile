# PHP CLI and PHP-FPM of one version, with the extensions the tool needs (sodium is built in), and `ps`,
# through which the tool sees the store's commands still running on the host.
ARG PHP_VERSION=8.3
FROM php:${PHP_VERSION}-fpm

RUN docker-php-ext-install pdo_mysql opcache \
    && apt-get update \
    && apt-get install -y --no-install-recommends git unzip procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2.10.3 /usr/bin/composer /usr/bin/composer

WORKDIR /app
