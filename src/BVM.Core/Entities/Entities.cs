using BVM.Core.Abstractions.Data;
using Microsoft.AspNetCore.Identity;
using Sweaj.Patterns.Data.Entities;

namespace BVM.Core.Entities
{
    public class AppUser : IdentityUser<Guid>, IKeyProvider<Guid> 
    {
        public Profile? Profile { get; set; }
    }
    public class AppRole : IdentityRole<Guid>, IKeyProvider<Guid>
    {
    }

    public class AppRoleClaim : IdentityRoleClaim<Guid>, IKeyProvider<int>
    {
    }

    public class AppUserClaim : IdentityUserClaim<Guid>, IKeyProvider<int>
    {
    }

    public class AppUserToken : IdentityUserToken<Guid>
    {
    }

    public class AppUserRole : IdentityUserRole<Guid>
    {
    }

    public class AppUserLogin : IdentityUserLogin<Guid>
    {
    }

    public class Profile : Entity
    {
        public ProfileInfo ProfileInfo { get; set; }
        public Guid ProfileInfoId { get; set; }

        public ProfileSetting ProfileSetting { get; set; }
        public Guid ProfileSettingId { get; set; }


        public ICollection<SocialMediaLink> SocialMediaLinks { get; set; }
    }

    public class ProfileInfo : Entity
    {
        [ProtectedPersonalData]
        public string FirstName { get; set; }

        [ProtectedPersonalData]
        public string LastName { get; set; }

        [ProtectedPersonalData]
        public string Email { get; set; }
    }

    public class ProfileSetting : Entity
    {
        public bool Setting { get; set; }

        public static ProfileSetting Default()
        {
            return new ProfileSetting
            {
                Setting = false,
            };
        }
    }

    /// <summary>
    /// Links a social media account to a profile and platform.
    /// </summary>
    public class SocialMediaLink : Entity, IIsActiveProvider
    {
        public Profile Profile { get; set; }
        public Guid ProfileId { get; set; }

        public Platform Platform { get; set; }
        public Guid PlatformId { get; set; }



        public bool IsActive { get; set; }
    }

    public class Platform : Entity, IIsActiveProvider
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Url { get; set; }
        public bool IsActive { get; set; }
    }

    public class PlatformToken : Entity, IIsActiveProvider
    {
        public Platform Platform { get; set; }
        public Guid PlatformId { get; set; }

        public string TokenTypeName { get; set; }
        public Type? GetTokenType()
        {
            return Type.GetType(TokenTypeName);
        }
        public string JsonToken { get; set; }
        public bool IsActive { get; set; }
    }
}
