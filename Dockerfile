# Dockerfile for php:8.5-apache
# Targets Render free tier: Apache on port 10000, Aiven MySQL SSL

FROM php:8.5-apache

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpng-dev \
        libjpeg62-turbo-dev \
        libfreetype6-dev \
        libzip-dev \
        libssl-dev \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# PHP extensions
# Note: In PHP 8.5, OPcache is built into core; mbstring, zlib, openssl, and fileinfo are also built-in.
RUN docker-php-ext-configure gd \
        --with-freetype \
        --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" \
        gd \
        pdo_mysql \
        mysqli \
        zip

# Apache modules
RUN a2enmod rewrite headers remoteip deflate expires

# Port configuration (Render uses port 10000)
RUN sed -i 's/^Listen 80$/Listen 10000/' /etc/apache2/ports.conf && \
    sed -i 's/<VirtualHost \*:80>/<VirtualHost *:10000>/' \
        /etc/apache2/sites-available/000-default.conf

# Virtual host configuration
COPY docker/apache-vhost.conf /etc/apache2/sites-available/000-default.conf
RUN sed -i 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/' /etc/apache2/conf-available/security.conf

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html
COPY . /var/www/html/

# Dependencies (must run BEFORE php.ini configuration)
RUN composer install --no-dev --optimize-autoloader --no-interaction

# PHP runtime configuration (applied AFTER composer install)
COPY docker/php.ini /usr/local/etc/php/conf.d/app.ini

# Permissions
RUN chown -R www-data:www-data /var/www/html \
    && find /var/www/html -type f -exec chmod 644 {} \; \
    && find /var/www/html -type d -exec chmod 755 {} \;

EXPOSE 10000

CMD ["apache2-foreground"]
