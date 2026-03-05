FROM php:8.2-apache

# instalar extensão mongodb
RUN pecl install mongodb \
    && docker-php-ext-enable mongodb

# instalar dependências e composer
RUN apt-get update && apt-get install -y git unzip curl \
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html

COPY . .

RUN composer install

# permissões compatíveis com OpenShift (UID random)
RUN chgrp -R 0 /var/www/html \
    && chmod -R g+rwX /var/www/html \
    && chgrp -R 0 /var/run/apache2 /var/log/apache2 /var/lock/apache2 \
    && chmod -R g+rwX /var/run/apache2 /var/log/apache2 /var/lock/apache2

EXPOSE 8080

# apache escutando 8080 (melhor para non-root)
RUN sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf \
    && sed -i 's/:80/:8080/' /etc/apache2/sites-available/000-default.conf
