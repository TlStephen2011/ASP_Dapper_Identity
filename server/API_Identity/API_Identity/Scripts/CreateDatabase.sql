create table Roles
(
    Id   int identity
        primary key,
    Name nvarchar(256) not null collate SQL_Latin1_General_CP1_CI_AS
)
go

create table Users
(
    Id           uniqueidentifier not null
        primary key,
    UserName     nvarchar(256)    not null collate SQL_Latin1_General_CP1_CI_AS
        unique,
    PasswordHash nvarchar(600)    not null collate SQL_Latin1_General_CP1_CI_AS
)
go

create table UserRoles
(
    UserId uniqueidentifier not null
        references Users,
    RoleId int              not null
        references Roles
)
go