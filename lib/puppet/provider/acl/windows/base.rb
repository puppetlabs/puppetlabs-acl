require 'pathname'

class Puppet::Provider::Acl
  module Windows
    module Base
      if Puppet::Util::Platform.windows?
        require Pathname.new(__FILE__).dirname + '../../../../' + 'puppet/type/acl/ace'
        require 'puppet/util/windows/security'
        require 'win32/security'
        require 'windows/security'
        require 'windows/file'

        REFRESH_SD        = true
        DO_NOT_REFRESH_SD = false
        ACL_FLAGS_WRITE   = ::Windows::File::GENERIC_WRITE | ::Windows::File::FILE_WRITE_DATA | ::Windows::File::FILE_APPEND_DATA
        ACL_FLAGS_READ    = ::Windows::File::GENERIC_READ | ::Windows::File::FILE_READ_DATA
        ACL_FLAGS_EXECUTE = ::Windows::File::GENERIC_EXECUTE | ::Windows::File::FILE_EXECUTE

        @security_descriptor = nil

        def get_current_permissions
          sd = get_security_descriptor(DO_NOT_REFRESH_SD)
          permissions = []
          permissions if sd.nil? || sd.dacl.nil?

          sd.dacl.each do |ace|
            permissions << Puppet::Type::Acl::Ace.new(convert_to_permissions_hash(ace))
          end

          permissions
        end

        def convert_to_permissions_hash(ace)
          return {} if ace.nil?

          sid = ace.sid
          identity = ace.sid_to_name(sid)
          rights = get_ace_rights_from_mask(ace)
          ace_type = get_ace_type(ace)
          child_types = get_ace_child_types(ace)
          affects = get_ace_propagation(ace)
          is_inherited = ace.inherited?
          hash = {'identity'=>"#{identity}", 'sid'=>"#{sid}", 'rights'=>rights,
                  'type'=>ace_type, 'child_types'=> child_types,
                  'affects'=>affects, 'is_inherited'=>is_inherited,
                  'mask'=>"#{ace.mask}" }

          hash
        end

        def get_ace_rights_from_mask(ace)
          rights = []
          return rights if ace.nil?

          # full
          if ace.mask & ::Windows::File::GENERIC_ALL != 0 ||
             (ace.mask & ::Windows::File::FILE_ALL_ACCESS) == ::Windows::File::FILE_ALL_ACCESS
            rights << 'full'
          end

          if rights == []
            if (ace.mask & ACL_FLAGS_WRITE) != 0
              rights << 'write'
            end
            if (ace.mask & ACL_FLAGS_READ) != 0
              rights << 'read'
            end
            if (ace.mask & ACL_FLAGS_EXECUTE) != 0
              rights << 'execute'
            end
          end

          # modify
          if rights == ['write','read','execute'] &&
             ace.mask & ::Windows::File::DELETE != 0
            rights = ['modify']
          end

          # rights are too specific, use mask
          if rights == []
            rights << 'mask_specific'
          end

          #todo decide on list
          #FILE_EXECUTE                 = 32
          #FILE_TRAVERSE                = 32

          rights
        end
        module_function :get_ace_rights_from_mask

        def get_ace_type(ace)
          return 'allow' if ace.nil?

          ace_type = case ace.type
            when 0 then 'allow'
            when 1 then 'deny'
          end

          ace_type
        end
        module_function :get_ace_type

        def get_ace_child_types(ace)
          return 'all' if ace.nil?

          # the order is on purpose
          child_types = 'none'
          child_types = 'objects' if ace.object_inherit?
          child_types = 'containers' if ace.container_inherit?
          child_types = 'all' if ace.object_inherit? && ace.container_inherit?

          child_types
        end
        module_function :get_ace_child_types

        def get_ace_propagation(ace)
          # http://msdn.microsoft.com/en-us/library/ms229747.aspx
          return 'all' if ace.nil?

          targets_self = true unless ace.inherit_only?
          targets_children = true if ace.object_inherit? || ace.container_inherit?
          targets_children_only = true if ace.inherit_only?

          # the order is on purpose
          affects = 'self_only' if targets_self
          affects = 'children_only' if targets_children_only
          affects = 'all' if targets_self && targets_children

          # Puppet::Util::Windows::AccessControlEntry defines the propagation flag but doesn't provide a method
          # http://msdn.microsoft.com/en-us/library/windows/desktop/ms692524(v=vs.85).aspx
          no_propagate_flag = 0x4
          propagate = ace.flags & no_propagate_flag != no_propagate_flag
          unless propagate
            affects = 'self_and_direct_children' if targets_self && targets_children
            affects = 'direct_children_only' if targets_children_only
          end

          affects
        end
        module_function :get_ace_propagation

        def are_permissions_insync?(current_permissions, specified_permissions, should_purge = false)
          return false if current_permissions.nil? && !specified_permissions.nil?

          current_local_permissions = current_permissions.select { |p| !p.is_inherited? }

          current_sync_check_perms = get_sync_checking_permissions(current_local_permissions)
          specified_sync_check_perms = get_sync_checking_permissions(specified_permissions)

          if should_purge
            current_sync_check_perms == specified_sync_check_perms
          else
            return true if specified_sync_check_perms.nil?

            # intersect permissions equal specified?
            # todo this will not guarantee order, so more work will need to be done here
            specified_sync_check_perms == current_sync_check_perms & specified_sync_check_perms
          end
        end

        def get_sync_checking_permissions(permissions)
          return permissions if permissions.nil?

          sync_checking_permissions = []
          permissions.each do |perm|
            sync_checking_permissions << {'identity'=>get_account_name(perm.identity),
                                   'sid'=> perm.sid || get_account_sid(perm.identity),
                                   'rights'=>perm.rights,
                                   'type'=>perm.type,
                                   'child_types'=>perm.child_types,
                                   'affects'=>perm.affects
            }
          end

          sync_checking_permissions
        end

        def convert_to_dacl(permissions)
          dacl = Puppet::Util::Windows::AccessControlList.new
          return dacl if permissions.nil? || permissions.empty?

          permissions.each do |permission|
            sid = get_account_sid(permission.identity)
            mask = get_account_mask(permission)
            flags = get_account_flags(permission)
            case permission.type
              when 'allow'
                dacl.allow(sid, mask, flags)
              when 'deny'
                dacl.deny(sid, mask, flags)
            end
          end

          dacl
        end

        def sync_dacl_current_to_should(current,should, should_purge = false)
          # todo: ensure the work is done here  - make changes on current and return it every time


          #require 'pry';binding.pry
          return current
        end

        def get_current_owner
          sd = get_security_descriptor

          sd.owner unless sd.nil?
        end

        def get_current_group
          sd = get_security_descriptor

          sd.group unless sd.nil?
        end

        def is_account_insync?(current, should)
          return false unless current

          should_empty = should.nil? || should.empty?
          return false if current.empty? != should_empty

          get_account_sid(current) == get_account_sid(should)
        end

        def get_account_sid(name)
          Puppet::Util::Windows::Security.name_to_sid(name)
        end

        def get_account_name(current_value)
          Puppet::Util::Windows::Security.sid_to_name(get_account_sid(current_value))
        end

        def get_account_mask(permission)
          return permission.mask if permission.mask

          mask = case @resource[:target_type]
            when :file
              begin
                #todo generate proper mask based on permissions
              end
          end

          mask
        end

        def get_account_flags(permission)
          # http://msdn.microsoft.com/en-us/library/ms229747.aspx
          flags = 0x0

          case permission.child_types
            when "all"
              flags = flags | Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE | Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE
            when "objects"
              flags = flags | Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE
            when "containers"
              flags = flags | Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE
          end

          case permission.affects
            when "self_only"
              flags =  0x0
            when "children_only"
              flags = flags | Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE
            when "self_and_direct_children_only"
              flags = flags | Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE
            when "direct_children_only"
              flags = flags | Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE | Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE
          end

          if (permission.child_types == "none" && flags != 0x0)
            Puppet.warning("If child_types => 'none', affects => value will be ignored. Please remove affects or set affects => 'all' or affects => 'self_only' to remove this warning.")
            flags = 0x0
          end

          flags
        end
        module_function :get_account_flags

        def is_inheriting_permissions?
          sd = get_security_descriptor

          return !sd.protect unless sd.nil?

          # default true
          true
        end

        def get_security_descriptor(refresh_sd = DO_NOT_REFRESH_SD)
          refresh_sd ||= false
          if @security_descriptor.nil? || refresh_sd
            sd = nil
            case @resource[:target_type]
              when :file
                begin
                  sd = Puppet::Util::Windows::Security.get_security_descriptor(@resource[:target])
                rescue => detail
                  raise Puppet::Error, "Failed to get security descriptor for path '#{@resource[:target]}': #{detail}", detail.backtrace
                end
            end

            @security_descriptor = sd
          end

          @security_descriptor
        end

        def set_security_descriptor(security_descriptor)
          case @resource[:target_type]
            when :file
              begin
                Puppet::Util::Windows::Security.set_security_descriptor(@resource[:target], security_descriptor)
              rescue => detail
                raise Puppet::Error, "Failed to set security descriptor for path '#{@resource[:target]}': #{detail}", detail.backtrace
              end
          end

          # flush out the cached sd
          get_security_descriptor(REFRESH_SD)
        end
      end
    end
  end
end

#todo legacy - check to see if method exists for Puppet::Util::Windows::Security.get_security_descriptor, if not - we'll need to create it
