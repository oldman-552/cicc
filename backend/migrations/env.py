from alembic import context
from sqlalchemy import engine_from_config, pool
from backend.app.db import Base, DATABASE_URL
from backend.app import models  # noqa
config = context.config
config.set_main_option('sqlalchemy.url', DATABASE_URL.replace('%', '%%'))
target_metadata = Base.metadata
if context.is_offline_mode():
    context.configure(url=DATABASE_URL, target_metadata=target_metadata, literal_binds=True, dialect_opts={'paramstyle':'named'})
    with context.begin_transaction(): context.run_migrations()
else:
    engine=engine_from_config(config.get_section(config.config_ini_section),prefix='sqlalchemy.',poolclass=pool.NullPool)
    with engine.connect() as connection:
        # SQLite uses migration-installed triggers instead of workspace FKs because
        # adding FKs requires rebuilding parent tables with existing dependent rows.
        # PostgreSQL uses real named FKs. Keep other metadata checks active.
        def include_object(obj,name,type_,reflected,compare_to):
            if connection.dialect.name=='sqlite' and type_=='foreign_key_constraint' and name and name.startswith('cicc_') and name.endswith('_workspace_fk'):
                return False
            return True
        context.configure(connection=connection,target_metadata=target_metadata,compare_type=True,include_object=include_object)
        with context.begin_transaction(): context.run_migrations()
