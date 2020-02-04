#!/bin/sh
rm -rf modules_pdksync/puppetlabs-acl/Gemfile.lock;rm -rf modules_pdksync/puppetlabs-acl/.bundle
bundle install --path .bundle/gems/ --jobs 4
bundle exec rake 'litmus:provision_list[default]'
bundle exec rake litmus:install_agent
bundle exec rake litmus:install_module
bundle exec rake litmus:acceptance:parallel
bundle exec rake litmus:tear_down
