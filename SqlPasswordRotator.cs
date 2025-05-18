using System;
using System.Data.SqlClient;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using System.Text;

namespace SqlPasswordRotator
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // Load configuration
                IConfiguration config = new ConfigurationBuilder()
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .Build();

                // Read configuration settings
                string connectionString = config.GetConnectionString("SqlConnection");
                string loginToUpdate = config["SqlSettings:LoginToUpdate"];
                bool generateRandomPassword = bool.Parse(config["SqlSettings:GenerateRandomPassword"]);
                string newPassword = generateRandomPassword ? GenerateStrongPassword() : config["SqlSettings:NewPassword"];
                
                // Validate configuration
                if (string.IsNullOrEmpty(connectionString) || string.IsNullOrEmpty(loginToUpdate))
                {
                    Console.WriteLine("Error: Connection string or login name is missing in configuration.");
                    return;
                }

                if (!generateRandomPassword && string.IsNullOrEmpty(newPassword))
                {
                    Console.WriteLine("Error: New password is not specified in configuration and random generation is disabled.");
                    return;
                }

                // Update SQL login password
                UpdateSqlLoginPassword(connectionString, loginToUpdate, newPassword);
                
                // Output result
                Console.WriteLine($"Password for SQL login '{loginToUpdate}' has been successfully updated.");
                
                // If randomly generated, show the new password
                if (generateRandomPassword)
                {
                    Console.WriteLine($"New generated password: {newPassword}");
                    Console.WriteLine("Make sure to securely store this password!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
            }
        }

        static void UpdateSqlLoginPassword(string connectionString, string loginName, string newPassword)
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                Console.WriteLine("Connected to SQL Server successfully.");

                // Escape single quotes in login name and password to prevent SQL injection
                loginName = loginName.Replace("'", "''");
                newPassword = newPassword.Replace("'", "''");

                // Create SQL command to alter login with new password
                string query = $"ALTER LOGIN [{loginName}] WITH PASSWORD = '{newPassword}'";
                
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.ExecuteNonQuery();
                }
            }
        }

        static string GenerateStrongPassword(int length = 16)
        {
            // Define character sets
            const string uppercaseChars = "ABCDEFGHJKLMNPQRSTUVWXYZ";  // excluding I and O (can be confused with 1 and 0)
            const string lowercaseChars = "abcdefghijkmnopqrstuvwxyz";  // excluding l (can be confused with 1)
            const string numberChars = "23456789";  // excluding 0 and 1 (can be confused with O and l)
            const string specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?";
            
            // Combine all sets
            string allChars = uppercaseChars + lowercaseChars + numberChars + specialChars;
            
            // Create random bytes
            byte[] randomBytes = new byte[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }
            
            // Build password
            StringBuilder password = new StringBuilder();
            
            // Ensure at least one character from each set
            password.Append(uppercaseChars[randomBytes[0] % uppercaseChars.Length]);
            password.Append(lowercaseChars[randomBytes[1] % lowercaseChars.Length]);
            password.Append(numberChars[randomBytes[2] % numberChars.Length]);
            password.Append(specialChars[randomBytes[3] % specialChars.Length]);
            
            // Fill the rest randomly
            for (int i = 4; i < length; i++)
            {
                password.Append(allChars[randomBytes[i] % allChars.Length]);
            }
            
            // Shuffle the password (Fisher-Yates algorithm)
            char[] passwordArray = password.ToString().ToCharArray();
            for (int i = passwordArray.Length - 1; i > 0; i--)
            {
                int j = randomBytes[i] % (i + 1);
                char temp = passwordArray[i];
                passwordArray[i] = passwordArray[j];
                passwordArray[j] = temp;
            }
            
            return new string(passwordArray);
        }
    }
}
