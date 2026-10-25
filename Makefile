dev:
	uv run python manage.py runserver

test:
	uv run python manage.py test apps.core.tests apps.logger.tests
