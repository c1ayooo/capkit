# Deliberately vulnerable target for the M2 exit test (docs ROADMAP M2).
#
# It is a fixture, not a product: exec.php has a command injection on purpose,
# the web root is writable so a dropped shell can land there, and login.php uses
# a trivially guessable account. Never expose it. It binds to loopback in the
# run command used by STATE.md.
FROM php:8.2-apache
COPY app/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
