package com.example.application;

import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.Unit;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.formlayout.FormLayout;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import org.springframework.beans.factory.annotation.Autowired;

@Route("")
@PageTitle("JWT Generator")
public class MainView extends VerticalLayout {

    private final TokenService tokenService;

    private final TextField clientIdField = new TextField("Client ID");
    private final PasswordField clientSecretField = new PasswordField("Client Secret");
    private final ComboBox<EnvironmentOption> environmentCombo = new ComboBox<>("Environnement");
    private final Button generateButton = new Button("Générer un JWT");

    @Autowired
    public MainView(TokenService tokenService) {
        this.tokenService = tokenService;
        setSizeFull();
        setSpacing(false);
        setPadding(true);
        setJustifyContentMode(JustifyContentMode.CENTER);
        setAlignItems(FlexComponent.Alignment.CENTER);

        VerticalLayout content = new VerticalLayout();
        content.setSpacing(true);
        content.setPadding(false);
        content.setAlignItems(FlexComponent.Alignment.STRETCH);
        content.setWidth(400, Unit.PIXELS);

        H1 header = new H1("Générateur de JWT");
        header.getStyle().set("margin-top", "0");
        header.getStyle().set("margin-bottom", "var(--lumo-space-m)");
        content.add(header);

        FormLayout formLayout = new FormLayout();
        formLayout.setResponsiveSteps(new FormLayout.ResponsiveStep("0", 1));

        clientIdField.setRequiredIndicatorVisible(true);
        clientSecretField.setRequiredIndicatorVisible(true);
        clientSecretField.setRevealButtonVisible(true);

        environmentCombo.setItems(EnvironmentOption.values());
        environmentCombo.setItemLabelGenerator(EnvironmentOption::getLabel);
        environmentCombo.setRequiredIndicatorVisible(true);
        environmentCombo.setAllowCustomValue(false);

        generateButton.addClickListener(event -> handleGenerate());
        generateButton.setWidthFull();

        formLayout.add(clientIdField, clientSecretField, environmentCombo);
        content.add(formLayout, generateButton);

        add(content);
    }

    private void handleGenerate() {
        if (clientIdField.isEmpty() || clientSecretField.isEmpty() || environmentCombo.isEmpty()) {
            Notification warning = Notification.show("Veuillez renseigner tous les champs.");
            warning.addThemeVariants(NotificationVariant.LUMO_ERROR);
            return;
        }

        EnvironmentOption selectedEnvironment = environmentCombo.getValue();

        TokenRequest request = new TokenRequest(
                clientIdField.getValue(),
                clientSecretField.getValue(),
                selectedEnvironment.getUrl()
        );

        String token = tokenService.getToken(request);
        Notification notification = Notification.show(
                "JWT généré pour " + selectedEnvironment.getLabel() + " : " + token,
                5000,
                Notification.Position.MIDDLE
        );
        notification.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
    }

    private enum EnvironmentOption {
        STAGING("Staging", "https://onelogin.stg.axa.com/as/token.oauth2"),
        PRODUCTION("Production", "https://onelogin.stg.axa.com/as/token.oauth2");

        private final String label;
        private final String url;

        EnvironmentOption(String label, String url) {
            this.label = label;
            this.url = url;
        }

        public String getLabel() {
            return label;
        }

        public String getUrl() {
            return url;
        }
    }
}
