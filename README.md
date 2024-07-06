# m_sqlauth.cpp #
### 2024 Jean "reverse" Chevronnet ###
Module for Anope IRC Services v2.1, lets users authenticate with
credentials stored in a pre-existing SQL server instead of the internal
Anope database.

# Licence #
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/)

# What this do? #
Add support for anope's module enc_bcrypt password's.
# Configuration #
Add this configuration block in your conf/modules.conf file
```
    module
    {
        name = "m_sqlauth"

        /* SQL engine to use. */
        engine = "mysql/main"

        /* Query to send
         *
         * @a@ -> user's account name
         * @p@ -> user's password 
         * @n@ -> user's nickname
         * @i@ -> user's IP
         *
         */
        query = "SELECT `pass`,`email` FROM `users` WHERE `nickname` = @n@"

        /*
         * If set, the reason to give the users who try to "/msg NickServ REGISTER". If not set, then registration is not blocked. 
         */
        disable_reason = "To register a new account navigate to http://www.test.fr/register/"

        /*
         * If set, the reason to give the users who try to "/msg NickServ SET EMAIL". If not set, then email changing is not blocked.
         */
        disable_email_reason = "To change your e-mail address navigate to http://www.test.fr/change/"
    }