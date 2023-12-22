import db
import app
def create_sample_initiatives():
    with app.app_context():  # Гарантирует, что вы находитесь в контексте приложения Flask
        existing_count = Initiative.query.count()
        if existing_count < 100:
            for i in range(existing_count + 1, 101):  # Creates up to 100 initiatives
                initiative = Initiative(
                    title=f"Initiative {i}",
                    description=f"Description for Initiative {i}",
                    user_id=2  # Предполагается, что 2 — это идентификатор существующего пользователя.
                )
                db.session.add(initiative)
            db.session.commit()
            #print(f"Added {100 - existing_count} new initiatives.")

create_sample_initiatives()