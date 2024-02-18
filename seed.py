from src import db
from src.models.users import User, Role, User_role
from src.models.networkautomation import DeviceManager, NetworkManager, ConfigTemplate

def seed_data():
    # Create roles
    admin_role = Role(name='Admin', permissions='all')
    user_role = Role(name='User', permissions='read')

    # Add roles to database
    db.session.add(admin_role)
    db.session.add(user_role)
    db.session.commit()

    # Create users
    admin_user = User(username='admin', password='password')
    admin_user.roles.append(admin_role)

    user_user = User(username='user', password='password')
    user_user.roles.append(user_role)

    # Add users to database
    db.session.add(admin_user)
    db.session.add(user_user)
    db.session.commit()

if __name__ == '__main__':
    seed_data()
