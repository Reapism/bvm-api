
# Add Migration
`
dotnet ef migrations add Init --project .\src\BVM.WebApi --output-dir Infrastructure/Migrations 
`

# Update Migration
`
dotnet ef database update
`
## With Verbosity
`
Update-Database -Verbose
`

# Remove Migration
`
dotnet ef migrations remove
`

# List Migration
`
dotnet ef migrations list
`

# [Resetting all migrations](https://learn.microsoft.com/en-us/ef/core/managing-schemas/migrations/managing?tabs=dotnet-core-cli)

In some extreme cases, it may be necessary to remove all migrations and start over. This can be easily done by deleting your Migrations folder and dropping your database; at that point you can create a new initial migration, which will contain your entire current schema.

It's also possible to reset all migrations and create a single one without losing your data. This is sometimes called "squashing", and involves some manual work:

1. Back up your database, in case something goes wrong.
2. In your database, delete all rows from the migrations history table (e.g. DELETE FROM [__EFMigrationsHistory] on SQL Server).
3. Delete your Migrations folder.
4. Create a new migration and generate a SQL script for it (dotnet ef migrations script).
5. Insert a single row into the migrations history, to record that the first migration has already been applied, since your tables are already there. The insert SQL is the last operation in the SQL script generated above, and resembles the following (don't forget to update the values): 