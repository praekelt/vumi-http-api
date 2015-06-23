from vumi.application import ApplicationWorker


class VumiApiWorkerConfig(ApplicationWorker.CONFIG_CLASS):
    pass


class VumiApiWorker(ApplicationWorker):
    CONFIG_CLASS = VumiApiWorkerConfig

    def setup_application(self):
        self.config = self.get_static_config()
        # TODO Start HTTP server

    def teardown_application(self):
        pass

    def consume_user_message(self, message):
        # TODO: Message handling
        pass

    def consume_event(self, event):
        # TODO: Event handling
        pass

    def consume_ack(self, event):
        return self.consume_event(event)

    def consume_nack(self, event):
        return self.consume_event(event)

    def consume_delivery_report(self, event):
        return self.consume_event(event)

    def consume_unknown_event(self, event):
        return self.consume_event(event)
