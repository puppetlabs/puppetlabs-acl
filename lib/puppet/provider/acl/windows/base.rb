class Puppet::Provider::Acl
  module Windows
    module Base
      # include all requires here
      require 'puppet/type/acl/ace'
      require 'puppet/util/windows/security'
      require 'puppet/provider/acl/windows/ffi'
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

        sd.dacl.each do |perm|
          permissions << Puppet::Type::Acl::Ace.new(convert_to_permissions_hash(perm))
        end

        permissions
      end

      def convert_to_permissions_hash(ace)
        hash = {}
        hash if ace.nil?

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
        if ace.mask & ::Windows::File::GENERIC_ALL != 0 #||
           #ace.mask & ::Windows::File::STANDARD_RIGHTS_ALL != 0
          rights << 'full'
        end

        if rights == []
          if ace.mask & ACL_FLAGS_WRITE != 0
            rights << 'write'
          end
          if ace.mask & ACL_FLAGS_READ != 0
            rights << 'read'
          end
          if ace.mask & ACL_FLAGS_EXECUTE != 0
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
        #todo decide whether STANDARD_RIGHTS_ALL is part of full access
        #STANDARD_RIGHTS_ALL          = 0x1F0000
        #SPECIFIC_RIGHTS_ALL          = 0xFFFF

        rights
      end
      module_function :get_ace_rights_from_mask

      def get_ace_type(ace)
        ace_type = 'allow'
        return ace_type if ace.nil?

        case ace.type
          when 0 then ace_type ='allow'
          when 1 then ace_type = 'deny'
        end

        ace_type
      end
      module_function :get_ace_type

      def get_ace_child_types(ace)
        child_types = 'all'
        return child_types if ace.nil?

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
        affects = 'all'
        return affects if ace.nil?

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

      def get_current_owner
        sd = get_security_descriptor(DO_NOT_REFRESH_SD)

        sd.owner unless sd.nil?
      end

      def is_inheriting_permissions?
        sd = get_security_descriptor(DO_NOT_REFRESH_SD)

        !sd.protect unless sd.nil?

        # assume true
        return :true
      end

      def get_security_descriptor(refresh_sd)
        refresh_sd ||= false
        if @security_descriptor.nil? || refresh_sd
          sd = nil
          case @resource[:target_type]
            when :file
              sd = Puppet::Util::Windows::Security.get_security_descriptor(@resource[:target])
          end

          @security_descriptor = sd
        end

        @security_descriptor
      end
    end
  end
end

#todo legacy - check to see if method exists for Puppet::Util::Windows::Security.get_security_descriptor, if not - we'll need to create it
