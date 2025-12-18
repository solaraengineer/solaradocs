import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async


class DocumentConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.project_id = self.scope['url_route']['kwargs']['project_id']
        self.room_group_name = f'doc_{self.project_id}'
        self.user = self.scope['user']

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'user_joined',
                'username': self.user.username if self.user.is_authenticated else 'Anonymous'
            }
        )

    async def disconnect(self, close_code):
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'user_left',
                'username': self.user.username if self.user.is_authenticated else 'Anonymous'
            }
        )

        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        msg_type = data.get('type')

        if msg_type == 'delta':
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'broadcast_delta',
                    'delta': data.get('delta'),
                    'username': self.user.username if self.user.is_authenticated else 'Anonymous',
                    'sender_channel': self.channel_name
                }
            )

        elif msg_type == 'cursor':
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'broadcast_cursor',
                    'cursor': data.get('cursor'),
                    'username': self.user.username if self.user.is_authenticated else 'Anonymous',
                    'sender_channel': self.channel_name
                }
            )

        elif msg_type == 'typing':
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'broadcast_typing',
                    'username': self.user.username if self.user.is_authenticated else 'Anonymous',
                    'sender_channel': self.channel_name
                }
            )

    async def broadcast_delta(self, event):
        if self.channel_name != event['sender_channel']:
            await self.send(text_data=json.dumps({
                'type': 'delta',
                'delta': event['delta'],
                'username': event['username']
            }))

    async def broadcast_cursor(self, event):
        if self.channel_name != event['sender_channel']:
            await self.send(text_data=json.dumps({
                'type': 'cursor',
                'cursor': event['cursor'],
                'username': event['username']
            }))

    async def broadcast_typing(self, event):
        if self.channel_name != event['sender_channel']:
            await self.send(text_data=json.dumps({
                'type': 'typing',
                'username': event['username']
            }))

    async def user_joined(self, event):
        await self.send(text_data=json.dumps({
            'type': 'user_joined',
            'username': event['username']
        }))

    async def user_left(self, event):
        await self.send(text_data=json.dumps({
            'type': 'user_left',
            'username': event['username']
        }))