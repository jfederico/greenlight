# frozen_string_literal: true

# BigBlueButton open source conferencing system - http://www.bigbluebutton.org/.
#
# Copyright (c) 2018 BigBlueButton Inc. and by respective authors (see below).
#
# This program is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free Software
# Foundation; either version 3.0 of the License, or (at your option) any later
# version.
#
# BigBlueButton is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with BigBlueButton; if not, see <http://www.gnu.org/licenses/>.

require 'bbb_api'

module OmniauthOptions
  module_function

  include BbbApi

  def omniauth_options(env)
    if Rails.configuration.loadbalanced_configuration
      protocol = Rails.env.production? ? "https" : env["rack.url_scheme"]
      protocol = "https"
      user_domain = parse_user_domain(env["SERVER_NAME"])
      if env['omniauth.strategy'].options[:name] == "bn_launcher"
        customer_redirect_url = protocol + "://" + env["SERVER_NAME"] + ":" + env["SERVER_PORT"]
        env['omniauth.strategy'].options[:customer] = user_domain
        env['omniauth.strategy'].options[:customer_redirect_url] = customer_redirect_url
        env['omniauth.strategy'].options[:default_callback_url] = Rails.configuration.gl_callback_url

        # This is only used in the old launcher and should eventually be removed
        env['omniauth.strategy'].options[:checksum] = generate_checksum(user_domain, customer_redirect_url,
          Rails.configuration.launcher_secret)
      elsif env['omniauth.strategy'].options[:name] == "openid_connect"
        Rails.logger.info "+++++++++++++++++++++++++++++++++"
        provider_info = retrieve_provider_info(user_domain, 'api2', 'getUserGreenlightCredentials')
        Rails.logger.info provider_info.to_json
        Rails.logger.info provider_info['BN_CONNECT_CLIENT_ID']
        env['omniauth.strategy'].options[:issuer] = provider_info['BN_CONNECT_ISSUER']
        env['omniauth.strategy'].options[:client_options].identifier = provider_info['BN_CONNECT_CLIENT_ID']
        env['omniauth.strategy'].options[:client_options].secret = provider_info['BN_CONNECT_CLIENT_SECRET']
      end
    elsif env['omniauth.strategy'].options[:name] == "google"
      set_hd(env, ENV['GOOGLE_OAUTH2_HD'])
    elsif env['omniauth.strategy'].options[:name] == "office365"
      set_hd(env, ENV['OFFICE365_HD'])
    elsif env['omniauth.strategy'].options[:name] == "openid_connect"
      set_hd(env, ENV['OPENID_CONNECT_HD'])
    end
  end

  # Limits the domain that can be used with the provider
  def set_hd(env, hd)
    if hd
      hd_opts = hd.split(',')
      env['omniauth.strategy'].options[:hd] = if hd_opts.empty?
        nil
      elsif hd_opts.length == 1
        hd_opts[0]
      else
        hd_opts
      end
    end
  end

  # Parses the url for the user domain
  def parse_user_domain(hostname)
    return hostname.split('.').first if Rails.configuration.url_host.empty?
    Rails.configuration.url_host.split(',').each do |url_host|
      return hostname.chomp(url_host).chomp('.') if hostname.include?(url_host)
    end
    ''
  end

  # Generates a checksum to use alongside the omniauth request
  def generate_checksum(user_domain, redirect_url, secret)
    string = user_domain + redirect_url + secret
    OpenSSL::Digest.digest('sha1', string).unpack1("H*")
  end
end
