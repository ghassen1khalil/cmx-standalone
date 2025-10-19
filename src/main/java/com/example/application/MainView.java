package com.example.application;

import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.formlayout.FormLayout;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.LinkedHashMap;
import java.util.Map;

@Route("")
@PageTitle("JWT Generator")
public class MainView extends VerticalLayout {

    private final TokenService tokenService;

    private final TextField clientIdField = new TextField("Client ID");
    private final PasswordField clientSecretField = new PasswordField("Client Secret");
    private final ComboBox<String> environmentCombo = new ComboBox<>("Environnement");
    private final Button generateButton = new Button("Générer un JWT");

    @Autowired
    public MainView(TokenService tokenService) {
        this.tokenService = tokenService;
        setSizeFull();
        setAlignItems(Alignment.CENTER);
        setJustifyContentMode(JustifyContentMode.CENTER);

        FormLayout formLayout = new FormLayout();
        formLayout.setMaxWidth("400px");

        clientIdField.setRequired(true);
        clientSecretField.setRequired(true);

        Map<String, String> environments = new LinkedHashMap<>();
        environments.put("Staging", "https://onelogin.stg.axa.com/as/token.oauth2");
        environments.put("Production", "https://onelogin.stg.axa.com/as/token.oauth2");
        environmentCombo.setItems(environments.values());
        environmentCombo.setItemLabelGenerator(value -> environments.entrySet().stream()
                .filter(entry -> entry.getValue().equals(value))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(value));
        environmentCombo.setRequired(true);

        generateButton.addClickListener(event -> handleGenerate(environments));

        formLayout.add(clientIdField, clientSecretField, environmentCombo, generateButton);
        add(formLayout);
    }

    private void handleGenerate(Map<String, String> environments) {
        if (clientIdField.isEmpty() || clientSecretField.isEmpty() || environmentCombo.isEmpty()) {
            Notification.show("Veuillez renseigner tous les champs.");
            return;
        }

        String environmentLabel = environments.entrySet().stream()
                .filter(entry -> entry.getValue().equals(environmentCombo.getValue()))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(environmentCombo.getValue());

        TokenRequest request = new TokenRequest(
                clientIdField.getValue(),
                clientSecretField.getValue(),
                environmentCombo.getValue()
        );

        String token = tokenService.getToken(request);
        Notification.show("JWT généré pour " + environmentLabel + " : " + token, 5000, Notification.Position.MIDDLE);
    }
}
