#!/bin/bash

echo "Restarting services..."

sudo systemctl restart elro, elro_app, nginx

echo "Done!"
