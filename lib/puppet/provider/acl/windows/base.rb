# frozen_string_literal: true

require 'pathname'

# Base provider for Access Control List type
class Puppet::Provider::Acl
  module Windows # rubocop:disable Style/ClassAndModuleChildren  Required to use the longform module name due to dependencies
    # Provides the detailed implementation details for the provider and should shield the provider from legacy
    # support implementations that would happen here.
    #
    # For information on ACE masks see:
    # {https://docs.microsoft.com/en-gb/previous-versions/windows/desktop/secrcw32prov/win32-ace Win32_ACE Class},
    # {https://docs.microsoft.com/en-gb/windows/desktop/SecAuthZ/standard-access-rights Standard Access Rights},
    # {https://docs.microsoft.com/en-gb/windows/desktop/SecAuthZ/generic-access-rights Generic Access Rights}
    #
    module Base
      # We need this as the libraries will not load properly on non-Windows platforms
      if Puppet::Util::Platform.windows?
        require Pathname.new(__FILE__).dirname + '../../../../' + 'puppet/type/acl/ace'
        require 'puppet/util/windows/security'
      end

      # Used to specify to flush out the SD cache.
      REFRESH_SD        = true
      # Used to specify to flush out the SD cache.
      DO_NOT_REFRESH_SD = false

      # Grants all possible access rights.
      GENERIC_ALL                  = 0x10000000
      # Grants write access.
      GENERIC_WRITE                = 0x40000000
      # Grants read access.
      GENERIC_READ                 = 0x80000000
      # Grants execute access.
      GENERIC_EXECUTE              = 0x20000000
      # Grants delete access.
      DELETE                       = 0x00010000

      # Synchronizes access and allows a process to wait for an object to enter the signaled state.
      SYNCHRONIZE                 = 0x100000
      # Combines DELETE, READ_CONTROL, WRITE_DAC, and WRITE_OWNER access.
      STANDARD_RIGHTS_REQUIRED    = 0xf0000
      # Currently defined to equal READ_CONTROL.
      STANDARD_RIGHTS_READ        = 0x20000
      # Currently defined to equal READ_CONTROL.
      STANDARD_RIGHTS_WRITE       = 0x20000
      # Currently defined to equal READ_CONTROL.
      STANDARD_RIGHTS_EXECUTE     = 0x20000

      # Grants the right to read data from the file. For a directory, this value grants the right
      # to list the contents of the directory.
      FILE_READ_DATA               = 1
      # Grants the right to write data to the file. For a directory, this value grants the right
      # to create a file in the directory.
      FILE_WRITE_DATA              = 2
      # Grants the right to append data to the file. For a directory, this value grants the right
      # to create a subdirectory.
      FILE_APPEND_DATA             = 4
      # Grants the right to read extended attributes.
      FILE_READ_EA                 = 8
      # Grants the right to write extended attributes.
      FILE_WRITE_EA                = 16
      # Grants the right to execute a file. For a directory, the directory can be traversed.
      FILE_EXECUTE                 = 32
      # Grants the right to delete a directory and all the files it contains (its children), even
      # if the files are read-only.
      FILE_DELETE_CHILD            = 64
      # Grants the right to read file attributes.
      FILE_READ_ATTRIBUTES         = 128
      # Grants the right to change file attributes.
      FILE_WRITE_ATTRIBUTES        = 256

      # Grants full read, write and execute permissions.
      FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF

      # A combination of masks providing a generic mask for reading files along with associated file and
      # extended attributes.
      FILE_GENERIC_READ =
        STANDARD_RIGHTS_READ |
        FILE_READ_DATA |
        FILE_READ_ATTRIBUTES |
        FILE_READ_EA |
        SYNCHRONIZE

      # A combination of masks providing a generic mask for writing files along with associated file and
      # extended attributes.
      FILE_GENERIC_WRITE =
        STANDARD_RIGHTS_WRITE |
        FILE_WRITE_DATA |
        FILE_WRITE_ATTRIBUTES |
        FILE_WRITE_EA |
        FILE_APPEND_DATA |
        SYNCHRONIZE

      # A combination of masks providing a generic mask for executing files.
      FILE_GENERIC_EXECUTE =
        STANDARD_RIGHTS_EXECUTE |
        FILE_READ_ATTRIBUTES |
        FILE_EXECUTE |
        SYNCHRONIZE

      @security_descriptor = nil

      # Converts an account name into an SID string
      #
      # @param [String] name Name+SID string
      # @return [Puppet::Util::Windows::SID] Converted SID
      #
      # @note Puppet 3.7 deprecated methods at old locations in favor of SID class
      def name_to_sid(name)
        if Puppet::Util::Windows::SID.respond_to?(:name_to_sid)
          Puppet::Util::Windows::SID.name_to_sid(name)
        else
          Puppet::Util::Windows::Security.name_to_sid(name)
        end
      end

      # Converts an SID string to an account name.
      #
      # @param [String] value SID string
      # @return [String] Extracted name
      def sid_to_name(value)
        if Puppet::Util::Windows::SID.respond_to?(:sid_to_name)
          Puppet::Util::Windows::SID.sid_to_name(value)
        else
          Puppet::Util::Windows::Security.sid_to_name(value)
        end
      end

      # Checks if supplied SID string is valid
      #
      # @param [String] string_sid SID string
      # @return [Bool] Whether supplied string is a valid SID
      def valid_sid?(string_sid)
        if Puppet::Util::Windows::SID.respond_to?(:valid_sid?)
          Puppet::Util::Windows::SID.valid_sid?(string_sid)
        else
          Puppet::Util::Windows::Security.valid_sid?(string_sid)
        end
      end

      # Retrieves permissions of current instance.
      #
      # @return [Array] ACEs of current instance.
      def get_current_permissions
        sd = get_security_descriptor(DO_NOT_REFRESH_SD)
        permissions = []
        unless sd.nil?
          permissions if sd.dacl.nil?
          sd.dacl.each do |ace|
            permissions << Puppet::Type::Acl::Ace.new(convert_to_permissions_hash(ace), self)
          end
        end
        permissions
      end

      # Converts an Ace object into a hash.
      #
      # @param [Puppet::Util::Windows::AccessControlEntry] ace
      # @return [Hash] Supplied ACE in the form of a hash.
      def convert_to_permissions_hash(ace)
        return {} if ace.nil?

        sid = ace.sid
        identity = sid_to_name(sid)
        rights = get_ace_rights_from_mask(ace)
        ace_type = get_ace_type(ace)
        child_types = get_ace_child_types(ace)
        affects = get_ace_propagation(ace)
        is_inherited = ace.inherited?
        hash = { 'identity' => identity.to_s, 'id' => sid.to_s, 'rights' => rights,
                 'perm_type' => ace_type, 'child_types' => child_types,
                 'affects' => affects, 'is_inherited' => is_inherited,
                 'mask' => ace.mask.to_s }

        hash
      end

      # Retrieves the access rights from an ACE's access mask.
      #
      # @param [Ace] ace
      # @return [Array] Collection of symbols corresponding to AccessRights
      def get_ace_rights_from_mask(ace)
        # TODO: v2 check that this is a file type and respond appropriately
        rights = []
        return rights if ace.nil?
        mask_specific_remainder = ace.mask

        # full
        if (ace.mask & GENERIC_ALL) == GENERIC_ALL ||
           (ace.mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS
          rights << :full
          mask_specific_remainder = 0
        end

        if rights == []
          if (ace.mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE
            rights << :write
            mask_specific_remainder &= ~FILE_GENERIC_WRITE
          end
          if (ace.mask & GENERIC_WRITE) == GENERIC_WRITE
            rights << :write
            mask_specific_remainder &= ~GENERIC_WRITE
          end

          if (ace.mask & FILE_GENERIC_READ) == FILE_GENERIC_READ
            rights << :read
            mask_specific_remainder &= ~FILE_GENERIC_READ
          end
          if (ace.mask & GENERIC_READ) == GENERIC_READ
            rights << :read
            mask_specific_remainder &= ~GENERIC_READ
          end

          if (ace.mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE
            rights << :execute
            mask_specific_remainder &= ~FILE_GENERIC_EXECUTE
          end
          if (ace.mask & GENERIC_EXECUTE) == GENERIC_EXECUTE
            rights << :execute
            mask_specific_remainder &= ~GENERIC_EXECUTE
          end
        end

        # modify
        # if the rights appending changes above, we'll
        # need to ensure this check is still good
        if rights == [:write, :read, :execute] &&
           (ace.mask & DELETE) == DELETE
          rights = [:modify]
          mask_specific_remainder &= ~DELETE
        end

        # rights are too specific, use mask
        if rights == []
          rights << :mask_specific
        elsif mask_specific_remainder != 0
          Puppet.debug("Remainder from #{ace.mask} is #{mask_specific_remainder}")
          rights = [:mask_specific]
        end

        rights
      end
      module_function :get_ace_rights_from_mask

      # Retrieves the type of a supplied ACE.
      #
      # @param [Puppet::Util::Windows::AccessControlEntry] ace
      # @return [Symbol] Type of supplied ACE
      def get_ace_type(ace)
        return :allow if ace.nil?

        ace_type = case ace.type
                   when Puppet::Util::Windows::AccessControlEntry::ACCESS_ALLOWED_ACE_TYPE then :allow
                   when Puppet::Util::Windows::AccessControlEntry::ACCESS_DENIED_ACE_TYPE then :deny
                   end

        ace_type
      end
      module_function :get_ace_type

      # Returns child types of supplied ACE.
      #
      # @param [Puppet::Util::Windows::AccessControlEntry] ace
      # @return [Symbol] Child types of supplied ACE.
      def get_ace_child_types(ace)
        return :all if ace.nil?

        # the order is on purpose
        child_types = :none
        child_types = :objects if ace.object_inherit?
        child_types = :containers if ace.container_inherit?
        child_types = :all if ace.object_inherit? && ace.container_inherit?

        child_types
      end
      module_function :get_ace_child_types

      # Retrieves propagation of supplied ACE.
      #
      # @param [Puppet::Util::Windows::AccessControlEntry] ace
      # @return [Symbol] Propagation rule of supplied ACE.
      def get_ace_propagation(ace)
        # http://msdn.microsoft.com/en-us/library/ms229747.aspx
        return :all if ace.nil?

        targets_self = true unless ace.inherit_only?
        targets_children = true if ace.object_inherit? || ace.container_inherit?
        targets_children_only = true if ace.inherit_only?

        # the order is on purpose
        affects = :self_only if targets_self
        affects = :children_only if targets_children_only
        affects = :all if targets_self && targets_children

        # Puppet::Util::Windows::AccessControlEntry defines the propagation flag but doesn't provide a method
        # http://msdn.microsoft.com/en-us/library/windows/desktop/ms692524(v=vs.85).aspx
        no_propagate_flag = 0x4
        propagate = ace.flags & no_propagate_flag != no_propagate_flag
        unless propagate
          affects = :self_and_direct_children_only if targets_self && targets_children
          affects = :direct_children_only if targets_children_only
        end

        affects
      end
      module_function :get_ace_propagation

      # TODO
      def are_permissions_insync?(current_permissions, specified_permissions, purge_value = :false)
        return false if current_permissions.nil? && !specified_permissions.nil? && purge_value != :listed_permissions

        purge_value = purge_value.to_s.downcase.to_sym unless purge_value.is_a?(Symbol)
        should_purge = purge_value == :true
        remove_permissions = purge_value == :listed_permissions
        current_local_permissions = if current_permissions.nil?
                                      []
                                    else
                                      current_permissions.reject { |p| p.inherited? }
                                    end

        if should_purge
          current_local_permissions == specified_permissions
        elsif remove_permissions
          return true if specified_permissions.nil?
          (specified_permissions & current_local_permissions) == []
        else
          return true if specified_permissions.nil?

          # intersect will return order by left item in intersect
          #  order is guaranteed checked when specified_permissions
          (current_local_permissions & specified_permissions) == specified_permissions
        end
      end

      # Converts an array of permissions into a DACL object.
      #
      # @param [Array] permissions Array of ACEs.
      # @return [Puppet::Util::Windows::AccessControlList] ACL of supplied ACEs.
      def convert_to_dacl(permissions)
        dacl = Puppet::Util::Windows::AccessControlList.new
        return dacl if permissions.nil? || permissions.empty?

        permissions.each do |permission|
          sid = get_account_id(permission.identity)
          mask = get_account_mask(permission)
          flags = get_account_flags(permission)
          case permission.perm_type
          when :allow
            dacl.allow(sid, mask, flags)
          when :deny
            dacl.deny(sid, mask, flags)
          end
        end

        dacl
      end

      # Retrieves mask from a supplied ACE
      #
      # @param [Puppet::Util::Windows::AccessControlEntry] permission
      # @param [Symbol] target_resource_type
      # @return [Integer] Extracted account mask
      def get_account_mask(permission, target_resource_type = :file)
        return 0 if permission.nil?
        return permission.mask.to_i if permission.mask
        return 0 if permission.rights.nil? || permission.rights.empty?

        mask = case target_resource_type
               when :file
                 begin
                   if permission.rights.include?(:full)
                     return FILE_ALL_ACCESS
                   end

                   if permission.rights.include?(:modify)
                     return DELETE |
                            FILE_GENERIC_WRITE |
                            FILE_GENERIC_READ  |
                            FILE_GENERIC_EXECUTE
                   end

                   filemask = 0x0
                   if permission.rights.include?(:write)
                     filemask |= FILE_GENERIC_WRITE
                   end

                   if permission.rights.include?(:read)
                     filemask |= FILE_GENERIC_READ
                   end

                   if permission.rights.include?(:execute)
                     filemask |= FILE_GENERIC_EXECUTE
                   end

                   filemask
                 end
               end
        mask
      end
      module_function :get_account_mask

      # Retrieve the propagation rule flags from a specified ACE.
      #
      # @param [Puppet::Util::Windows::AccessControlEntry] permission
      # @return [Array] Flags associated with ACE.
      def get_account_flags(permission)
        # http://msdn.microsoft.com/en-us/library/ms229747.aspx
        flags = 0x0

        case permission.child_types
        when :all
          flags = flags |
                  Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE
        when :objects
          flags |= Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE
        when :containers
          flags |= Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE
        end

        case permission.affects
        when :self_only
          flags = 0x0
        when :children_only
          flags |= Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE
        when :self_and_direct_children_only
          flags |= Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE
        when :direct_children_only
          flags = flags |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE
        end

        if permission.child_types == :none && flags != 0x0
          flags = 0x0
        end

        flags
      end
      module_function :get_account_flags

      # Ensures that the supplied DACL matches the additional supplied parameters.
      #
      # @param [Puppet::Util::Windows::AccessControlList] current_dacl
      # @param [Array] should_aces
      # @param [Boolean] should_purge
      # @param [Boolean] remove_permissions
      # @return [Array] Matching ACEs.
      def sync_aces(current_dacl, should_aces, should_purge = false, remove_permissions = false)
        if remove_permissions
          kept_aces = []
          current_dacl.each do |ace|
            next if ace.inherited?

            current_ace = Puppet::Type::Acl::Ace.new(convert_to_permissions_hash(ace), self)
            existing_aces = should_aces.select { |a| a.same?(current_ace) }
            next unless existing_aces.empty?

            kept_aces << current_ace
          end

          should_aces = kept_aces
        else
          return should_aces if should_purge

          current_dacl.each do |ace|
            # TODO: v2 should we warn if we have an existing inherited ace that matches?
            next if ace.inherited?

            current_ace = Puppet::Type::Acl::Ace.new(convert_to_permissions_hash(ace), self)
            existing_aces = should_aces.select { |a| a.same?(current_ace) }
            next unless existing_aces.empty?

            # munge in existing unmanaged aces
            case current_ace.perm_type
            when :deny
              last_allow_index = should_aces.index { |a| a.perm_type == :allow }
              should_aces.insert(last_allow_index, current_ace) if last_allow_index
              should_aces << current_ace unless last_allow_index
            when :allow
              should_aces << current_ace
            end
          end
        end

        should_aces
      end

      # Retrieves owner from current instance's SecurityDescriptor.
      #
      # @return [String] SID owner.
      def get_current_owner
        sd = get_security_descriptor

        sd&.owner
      end

      # Retrieves group from current instance's SecurityDescriptor.
      #
      # @return [String] SID group.
      def get_current_group
        sd = get_security_descriptor

        sd&.group
      end

      # Compares two SIDs to determine if they contain the same account id.
      #
      # @param [Puppet::Util::Windows::SID] current
      # @param [Puppet::Util::Windows::SID] should
      # @return [Bool] True if `current` account id is `should` account id.
      def account_insync?(current, should)
        return false unless current

        should_empty = should.nil? || should.empty?
        return false if current.empty? != should_empty

        get_account_id(current) == get_account_id(should)
      end

      # Converts an account name into an SID.
      #
      # @param [String] name
      # @return [Puppet::Util::Windows::SID] Converted SID.
      def get_account_id(name)
        # sometimes the name will come in with a SID
        # which will return nil when we call name_to_sid
        # if the user no longer exists
        return unless name
        if valid_sid?(name)
          name
        else
          name_to_sid(name)
        end
      end

      # Retrieves name from SID
      #
      # @param [Puppet::Util::Windows::SID] current_value
      # @return [String] If `current_value` contains name returns this else return `current_value`.
      def get_account_name(current_value)
        name = sid_to_name(get_account_id(current_value))

        name ? name : current_value
      end
      alias get_group_name get_account_name

      def inheriting_permissions?
        sd = get_security_descriptor

        return !sd.protect unless sd.nil?

        # default true
        true
      end

      # Retrieves the SecurityDescriptor of the current instance
      #
      # @param [Bool] refresh_sd Whether to refresh the current instance's SecurityDescriptor.
      # @return [Puppet::Util::Windows::SecurityDescriptor] Instance's SecurityDescriptors.
      def get_security_descriptor(refresh_sd = DO_NOT_REFRESH_SD)
        refresh_sd ||= false
        if @security_descriptor.nil? || refresh_sd
          sd = nil
          case @resource[:target_type]
          when :file
            begin
              sd = Puppet::Util::Windows::Security.get_security_descriptor(@resource[:target]) unless @resource.noop?
            rescue => detail
              raise Puppet::Error, "Failed to get security descriptor for path '#{@resource[:target]}': #{detail}", detail.backtrace
            end
          end

          @security_descriptor = sd
        end

        @security_descriptor
      end

      # Sets the instance's SecurityDescriptor
      #
      # @param [Puppet::Util::Windows::SecurityDescriptor] security_descriptor
      # @return [Puppet::Util::Windows::SecurityDescriptor] Returns set SecurityDescriptor
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

# TODO: v2 legacy - check to see if method exists for Puppet::Util::Windows::Security.get_security_descriptor, if not - we'll need to create it
