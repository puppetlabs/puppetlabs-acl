Puppet::Type.newtype(:acl) do
  @doc = <<-'EOT'
    Manages access control lists.  The `acl` type is typically
    used in when you need more complex management of permissions
    e.g. windows.

    Sample usage:

      ADD HERE LATER
  EOT

  feature :ace_order_required, "The provider determines if the order of access control entries (ACE) is required."

  newparam(:name) do
    desc "The name of the acl resource.  Used for uniqueness."
    isnamevar
  end

end
