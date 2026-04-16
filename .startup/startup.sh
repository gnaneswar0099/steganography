#!/bin/bash
# Configure PHP upload limits at startup
echo "upload_max_filesize = 50M" >> /usr/local/etc/php/conf.d/uploads.ini
echo "post_max_size = 50M" >> /usr/local/etc/php/conf.d/uploads.ini
echo "PHP upload limits configured"
