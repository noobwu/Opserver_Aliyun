using System.Configuration;

namespace StackExchange.Opserver.Models.Security
{
    /// <summary>
    /// Does this REALLY need an explanation?
    /// </summary>
    public class EveryonesReadOnlyProvider : SecurityProvider
    {
        public override bool IsAdmin => false;

        internal override bool InReadGroups(ISecurableModule settings) { return true; }
        public override bool InGroups(string groupNames, string accountName) { return true; }
        public override bool ValidateUser(string userName, string password) {
            var adminUsers = ConfigurationManager.AppSettings["AdminUsers"];
            if (string.IsNullOrEmpty(adminUsers))
            {
                return false;
            }
            var adminUsersArray = adminUsers.Split(new char[] { ',' }, System.StringSplitOptions.RemoveEmptyEntries);
            if (adminUsersArray == null || adminUsersArray.Length == 0)
            {
                return false;
            }
            foreach (var item in adminUsersArray)
            {
                string[] tmpUser = item.Split(new char[] { ':' }, System.StringSplitOptions.RemoveEmptyEntries);
                if (tmpUser != null && tmpUser.Length == 2)
                {
                    return userName == tmpUser[0] && password == tmpUser[1];
                }
            }
            return false;
        }
    }
}
