using Microsoft.EntityFrameworkCore;
using UserAuth.Models;

namespace UserAuth.Context
{
    public class AddDbcontext: DbContext
    {
        public AddDbcontext(DbContextOptions<AddDbcontext> options):base(options) 
        {   

        }
        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("users");
        }

    }
}
