FROM bref/x86-php74-base

RUN yum install -y php74-php-fpm php74-php-posix

RUN /bin/cat /opt/remi/php74/root/sbin/php-fpm > /bref/bin/php-fpm

RUN chmod +x /bref/bin/php-fpm

RUN /bin/cat /opt/remi/php74/root/lib64/php/modules/posix.so > /bref/php-modules/posix.so

RUN /bin/cat /lib64/libacl.so.1 > /bref/lib/libacl.so.1
RUN /bin/cat /lib64/libsystemd.so.0 > /bref/lib/libsystemd.so.0
RUN /bin/cat /lib64/libattr.so.1 > /bref/lib/libattr.so.1
RUN /bin/cat /lib64/libcap.so.2 > /bref/lib/libcap.so.2
RUN /bin/cat /lib64/liblz4.so.1 > /bref/lib/liblz4.so.1
RUN /bin/cat /lib64/libgcrypt.so.11 > /bref/lib/libgcrypt.so.11
RUN /bin/cat /lib64/libgpg-error.so.0 > /bref/lib/libgpg-error.so.0
RUN /bin/cat /lib64/libdw.so.1 > /bref/lib/libdw.so.1
RUN /bin/cat /lib64/libelf.so.1 > /bref/lib/libelf.so.1
RUN /bin/cat /lib64/libbz2.so.1 > /bref/lib/libbz2.so.1

FROM public.ecr.aws/lambda/provided:al2-x86_64

COPY --from=bref/x86-php74-base /bref /opt

COPY --from=0 /bref/bin/php-fpm /opt/bin/php-fpm
COPY --from=0 /bref/lib/* /opt/lib/
COPY --from=0 /bref/php-modules/* /opt/php-modules/

COPY --from=bref/x86-php74-ext-mbstring /opt/lib/* /opt/lib/
COPY --from=bref/x86-php74-ext-mbstring /opt/php-modules/* /opt/php-modules/

COPY --from=bref/x86-php74-ext-bcmath /opt/php-modules/bcmath.so /opt/php-modules/bcmath.so
COPY --from=bref/x86-php74-ext-ctype /opt/php-modules/ctype.so /opt/php-modules/ctype.so
COPY --from=bref/x86-php74-ext-dom /opt/php-modules/dom.so /opt/php-modules/dom.so
COPY --from=bref/x86-php74-ext-exif /opt/php-modules/exif.so /opt/php-modules/exif.so
COPY --from=bref/x86-php74-ext-fileinfo /opt/php-modules/fileinfo.so /opt/php-modules/fileinfo.so
COPY --from=bref/x86-php74-ext-ftp /opt/php-modules/ftp.so /opt/php-modules/ftp.so
COPY --from=bref/x86-php74-ext-gettext /opt/php-modules/gettext.so /opt/php-modules/gettext.so
COPY --from=bref/x86-php74-ext-iconv /opt/php-modules/iconv.so /opt/php-modules/iconv.so

COPY runtime/configuration/fpm/bref-fpm.ini /opt/php-ini/bref.ini
COPY runtime/configuration/php74.ini /opt/php-ini/php74.ini
COPY runtime/configuration/fpm/php-fpm.conf /opt/php-fpm/php-fpm.conf

COPY runtime/configuration/fpm/bootstrap-fpm /opt/bootstrap
COPY runtime/configuration/fpm/bootstrap-fpm /var/runtime/bootstrap

RUN chmod +x /opt/bootstrap
RUN chmod +x /var/runtime/bootstrap

COPY src/Toolbox/Runner.php /opt/bref-src/Toolbox/Runner.php
COPY src/Toolbox/VendorDownloader.php /opt/bref-src/Toolbox/VendorDownloader.php
COPY src/Toolbox/bootstrap.php /opt/bref-src/Toolbox/bootstrap.php
