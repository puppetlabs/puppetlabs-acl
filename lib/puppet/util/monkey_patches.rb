module Puppet::Util::MonkeyPatches
end


if Puppet::Util::Platform.windows?

  require 'win32/security'
  # http://stackoverflow.com/a/2954632/18475
  # only monkey patch older versions that have the flaw with certain accounts
  # and stripping what appears to be whitespace
  # we only want to path pre-FFI versions, and we have the luxury of knowing that
  # we will be skipping from 0.1.4 straight to the latest FFI-ed, fixed version
  # see https://github.com/djberg96/win32-security/issues/3
  if Gem.loaded_specs["win32-security"].version < Gem::Version.new('0.2.0')
    # monkey patch that bad boy
    Win32::Security::SID.class_eval do
      # Error class typically raised if any of the SID methods fail
      class Error < StandardError; end

      def initialize(account=nil, host=Socket.gethostname)
        if account.nil?
          htoken = [0].pack('L')
          bool   = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, htoken)
          errno  = GetLastError()

          if !bool
            if errno == ERROR_NO_TOKEN
              unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, htoken)
                raise get_last_error
              end
            else
              raise get_last_error(errno)
            end
          end

          htoken = htoken.unpack('V').first
          cbti = [0].pack('L')
          token_info = 0.chr * 36

          bool = GetTokenInformation(
              htoken,
              TokenOwner,
              token_info,
              token_info.size,
              cbti
          )

          unless bool
            raise Error, get_last_error
          end
        end

        bool   = false
        sid    = 0.chr * 80
        sid_cb = [sid.size].pack('L')

        domain_buf = 0.chr * 80
        domain_cch = [domain_buf.size].pack('L')

        sid_name_use = 0.chr * 4

        if account
          ordinal_val = account[0]
          ordinal_val = ordinal_val.ord if RUBY_VERSION.to_f >= 1.9
        else
          ordinal_val = nil
        end

        if ordinal_val.nil?
          bool = LookupAccountSid(
              nil,
              token_info.unpack('L')[0],
              sid,
              sid_cb,
              domain_buf,
              domain_cch,
              sid_name_use
          )
        elsif ordinal_val < 10 # Assume it's a binary SID.
          bool = LookupAccountSid(
              host,
              [account].pack('p*').unpack('L')[0],
              sid,
              sid_cb,
              domain_buf,
              domain_cch,
              sid_name_use
          )
        else
          bool = LookupAccountName(
              host,
              account,
              sid,
              sid_cb,
              domain_buf,
              domain_cch,
              sid_name_use
          )
        end

        unless bool
          raise Error, get_last_error
        end

        # The arguments are flipped depending on which path we took
        if ordinal_val.nil?
          buf = 0.chr * 260
          ptr = token_info.unpack('L')[0]
          memcpy(buf, ptr, token_info.size)
          @sid = buf.strip
          @account = sid.strip
        elsif ordinal_val < 10
          @sid     = account
          @account = sid.strip
        else
          # all that necessary just for these two lines
          length = GetLengthSid(sid)
          @sid = sid[0,length]
          @account = account
        end

        @host   = host
        @domain = domain_buf.strip

        @account_type = get_account_type(sid_name_use.unpack('L')[0])
      end
    end
  end


end
