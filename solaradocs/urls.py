from django.urls import path, include
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('setup/', views.setup, name='setup'),
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('accounts/', include('allauth.urls')),
    path('changeroles/', views.change_roles, name='change_roles'),
    path('about/', views.about, name='about'),
    path('collaborations/', views.collaborations, name='collaborations'),
    path('deleteproject/', views.delete_project, name='delete_project'),
    path('handlepending/', views.handle_pending, name='handle_pending'),
    path('', include('django_prometheus.urls')),
    path('docs/', views.docs, name='docs'),
    path('project/<int:project_id>/', views.project_detail, name='project_detail'),
    path('addpeople/', views.add_people, name='add_people'),
    path('deleteuser/', views.deleteuser, name='deleteuser'),
    path('save-doc/', views.save_docs, name='save_docs'),
    path('revert/', views.revert, name='revert'),
    path('logout/', views.logout, name='logout'),
    path('create-checkout-session/', views.create_checkout_session, name='create-checkout-session'),
    path('success/', views.success, name='success'),
    path('buy/', views.buy, name='buy'),
    path('gen/token', views.get_oauth_token, name='generate_token'),
    path('gen/editor/token', views.generate_editor_token, name='generate_token_editor'),
    path('webhook/stripe/', views.stripe_webhook, name='stripe_webhook'),
]