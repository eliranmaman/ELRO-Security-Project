#!/bin/bash

echo "Restarting services..."

sudo systemctl restart elro
sudo systemctl restart nginx

echo "Done!"
